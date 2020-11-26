<?php declare(strict_types = 1);

namespace Orisai\Auth\Bridge\NetteHttp;

use DateTimeInterface;
use Nette\Http\Session;
use Nette\Http\SessionSection;
use Orisai\Auth\Authentication\Data\CurrentExpiration;
use Orisai\Auth\Authentication\Data\CurrentLogin;
use Orisai\Auth\Authentication\Data\ExpiredLogin;
use Orisai\Auth\Authentication\Data\Logins;
use Orisai\Auth\Authentication\Exception\CannotRenewIdentity;
use Orisai\Auth\Authentication\Firewall;
use Orisai\Auth\Authentication\Identity;
use Orisai\Auth\Authentication\IdentityRenewer;
use Orisai\Auth\Authentication\LoginStorage;
use Orisai\Exceptions\Logic\InvalidArgument;
use Orisai\Exceptions\Logic\ShouldNotHappen;
use Orisai\Exceptions\Message;
use function assert;
use function sprintf;
use function time;

final class NetteSessionLoginStorage implements LoginStorage
{

	private const SESSION_PREFIX = 'orisai.auth';

	private string $namespace;
	private Session $session;
	private ?IdentityRenewer $identityRenewer;

	private ?Logins $logins = null;
	private int $expiredIdentitiesLimit = Firewall::EXPIRED_IDENTITIES_DEFAULT_LIMIT;

	public function __construct(string $namespace, Session $session, ?IdentityRenewer $identityRenewer = null)
	{
		$this->namespace = $namespace;
		$this->session = $session;
		$this->identityRenewer = $identityRenewer;
	}

	public function getIdentity(): ?Identity
	{
		if (!$this->session->exists()) {
			return null;
		}

		$login = $this->getLogins()->getCurrentLogin();

		return $login === null ? null : $login->getIdentity();
	}

	public function login(Identity $identity): void
	{
		$logins = $this->getLogins();

		$previousLogin = $logins->getCurrentLogin();
		if ($previousLogin !== null && $previousLogin->getIdentity()->getId() !== $identity->getId()) {
			$this->addExpiredLogin(new ExpiredLogin($previousLogin, $this::REASON_MANUAL));
		}

		$logins->setCurrentLogin(new CurrentLogin($identity, time()));

		$this->session->regenerateId();
	}

	/**
	 * @throws CannotRenewIdentity When user is not logged id
	 */
	public function renewIdentity(Identity $identity): void
	{
		$login = $this->getLogins()->getCurrentLogin();

		if ($login === null) {
			throw CannotRenewIdentity::create(self::class, __FUNCTION__);
		}

		$login->setIdentity($identity);
	}

	/**
	 * @phpstan-param self::REASON_* $reason
	 */
	public function logout(int $reason): void
	{
		$this->unauthenticate($reason, $this->getLogins());
	}

	/**
	 * @phpstan-param self::REASON_* $reason
	 */
	private function unauthenticate(int $reason, Logins $logins): void
	{
		$login = $logins->getCurrentLogin();

		if ($login === null) {
			return;
		}

		$this->session->regenerateId();
		$logins->removeCurrentLogin();
		$this->addExpiredLogin(new ExpiredLogin($login, $reason));
	}

	/**
	 * @throws ShouldNotHappen When expiration is set before user is logged in and firewall did not check
	 */
	public function setExpiration(DateTimeInterface $time): void
	{
		$login = $this->getLogins()->getCurrentLogin();

		if ($login === null) {
			throw ShouldNotHappen::create()
				->withMessage('Firewall should check whether user is logged in when expiration is set.');
		}

		$expirationTime = (int) $time->format('U');
		$delta = $expirationTime - time();
		$login->setExpiration(new CurrentExpiration($expirationTime, $delta));

		if ($delta <= 0) {
			$message = Message::create()
				->withContext('Trying to set login expiration time.')
				->withProblem('Expiration time is lower than current time.')
				->withSolution('Choose expiration time which is in future.');

			throw InvalidArgument::create()
				->withMessage($message);
		}
	}

	public function removeExpiration(): void
	{
		$login = $this->getLogins()->getCurrentLogin();

		if ($login === null) {
			return;
		}

		$login->removeExpiration();
	}

	private function addExpiredLogin(ExpiredLogin $login): void
	{
		$logins = $this->getLogins();
		$logins->addExpiredLogin($login);
		$logins->removeOldestExpiredLoginsAboveLimit($this->expiredIdentitiesLimit);
	}

	/**
	 * @return array<ExpiredLogin>
	 */
	public function getExpiredLogins(): array
	{
		if (!$this->session->exists()) {
			return [];
		}

		return $this->getLogins()->getExpiredLogins();
	}

	public function removeExpiredLogins(): void
	{
		$this->getLogins()->removeExpiredLogins();
	}

	/**
	 * @param int|string $id
	 */
	public function removeExpiredLogin($id): void
	{
		$this->getLogins()->removeExpiredLogin($id);
	}

	public function setExpiredIdentitiesLimit(int $count): void
	{
		$this->expiredIdentitiesLimit = $count;
		$this->getLogins()->removeOldestExpiredLoginsAboveLimit($count);
	}

	private function getSessionSection(): SessionSection
	{
		$sectionName = sprintf('%s.%s', self::SESSION_PREFIX, $this->namespace);

		$isNew = !$this->session->hasSection($sectionName);

		$section = $this->session->getSection($sectionName);
		$section->warnOnUndefined = true;

		if ($isNew) {
			$this->setDefaults($section);
		} else {
			$this->migrateData($section);
		}

		return $section;
	}

	public function getLogins(): Logins
	{
		if ($this->logins !== null) {
			return $this->logins;
		}

		$logins = $this->getSessionSection()->logins;
		assert($logins instanceof Logins);

		$this->checkInactivity($logins);
		$this->checkIdentity($logins);

		return $this->logins = $logins;
	}

	private function setDefaults(SessionSection $section): void
	{
		$section->version = 2;
		$section->logins = new Logins();
	}

	private function migrateData(SessionSection $section): void
	{
		if ($section->version !== 1) {
			return;
		}

		$section->version = 2;
		$section->logins = $logins = new Logins();

		if ($section->identity !== null) {
			$login = new CurrentLogin($section->identity, $section->authenticationTime ?? time());

			if ($section->expirationTime !== null && $section->expirationDelta !== null) {
				$expiration = new CurrentExpiration($section->expirationTime, $section->expirationDelta);
				$login->setExpiration($expiration);
			}

			if ($section->authenticated === true) {
				$logins->setCurrentLogin($login);
			} else {
				$logins->addExpiredLogin(new ExpiredLogin(
					$login,
					$section->logoutReason,
				));
			}
		}

		unset(
			$section->authenticated,
			$section->authenticationTime,
			$section->identity,
			$section->logoutReason,
			$section->expirationTime,
			$section->expirationDelta,
		);
	}

	private function checkInactivity(Logins $logins): void
	{
		$login = $logins->getCurrentLogin();

		if ($login === null) {
			return;
		}

		$expiration = $login->getExpiration();

		if ($expiration === null) {
			return;
		}

		if ($expiration->getTimestamp() < time()) {
			$this->unauthenticate(self::REASON_INACTIVITY, $logins);
		} else {
			$expiration->setTimestamp(time() + $expiration->getDelta());
		}
	}

	private function checkIdentity(Logins $logins): void
	{
		$login = $logins->getCurrentLogin();

		if ($login === null || $this->identityRenewer === null) {
			return;
		}

		$identity = $this->identityRenewer->renewIdentity($login->getIdentity());

		if ($identity === null) {
			$this->unauthenticate(self::REASON_INVALID_IDENTITY, $logins);
		} else {
			$login->setIdentity($identity);
		}
	}

}
