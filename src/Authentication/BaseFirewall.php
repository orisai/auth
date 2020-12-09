<?php declare(strict_types = 1);

namespace Orisai\Auth\Authentication;

use Brick\DateTime\Clock;
use Brick\DateTime\Clock\SystemClock;
use Brick\DateTime\Duration;
use Brick\DateTime\Instant;
use Orisai\Auth\Authentication\Data\CurrentExpiration;
use Orisai\Auth\Authentication\Data\CurrentLogin;
use Orisai\Auth\Authentication\Data\ExpiredLogin;
use Orisai\Auth\Authentication\Data\Logins;
use Orisai\Auth\Authentication\Exception\CannotAccessIdentity;
use Orisai\Auth\Authentication\Exception\CannotGetAuthenticationTime;
use Orisai\Auth\Authentication\Exception\CannotRenewIdentity;
use Orisai\Auth\Authentication\Exception\CannotSetExpiration;
use Orisai\Exceptions\Logic\InvalidArgument;
use Orisai\Exceptions\Message;

/**
 * @phpstan-template T of Identity
 * @phpstan-implements Firewall<T>
 */
abstract class BaseFirewall implements Firewall
{

	private LoginStorage $storage;

	/** @var IdentityRenewer<T> */
	private IdentityRenewer $renewer;

	private Clock $clock;

	protected ?Logins $logins = null;
	private int $expiredIdentitiesLimit = self::EXPIRED_IDENTITIES_DEFAULT_LIMIT;

	/**
	 * @param IdentityRenewer<T> $renewer
	 */
	public function __construct(LoginStorage $storage, IdentityRenewer $renewer, ?Clock $clock = null)
	{
		$this->storage = $storage;
		$this->renewer = $renewer;
		$this->clock = $clock ?? new SystemClock();
	}

	abstract protected function getNamespace(): string;

	public function isLoggedIn(): bool
	{
		return $this->fetchIdentity() !== null;
	}

	public function login(Identity $identity): void
	{
		$logins = $this->getLogins();

		$previousLogin = $logins->getCurrentLogin();
		if ($previousLogin !== null && $previousLogin->getIdentity()->getId() !== $identity->getId()) {
			$this->addExpiredLogin(new ExpiredLogin($previousLogin, $this::REASON_MANUAL));
		}

		$logins->setCurrentLogin(new CurrentLogin($identity, $this->clock->getTime()));

		$this->storage->regenerateSecurityToken($this->getNamespace());
	}

	/**
	 * @throws CannotRenewIdentity
	 */
	public function renewIdentity(Identity $identity): void
	{
		$login = $this->getLogins()->getCurrentLogin();

		if ($login === null) {
			throw CannotRenewIdentity::create(static::class, __FUNCTION__);
		}

		$login->setIdentity($identity);
	}

	public function logout(): void
	{
		$this->unauthenticate(self::REASON_MANUAL, $this->getLogins());
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

		$logins->removeCurrentLogin();
		$this->addExpiredLogin(new ExpiredLogin($login, $reason));

		$this->storage->regenerateSecurityToken($this->getNamespace());
	}

	/**
	 * @throws CannotAccessIdentity
	 */
	public function getIdentity(): Identity
	{
		$identity = $this->fetchIdentity();

		if ($identity === null) {
			throw CannotAccessIdentity::create(static::class, __FUNCTION__);
		}

		return $identity;
	}

	private function fetchIdentity(): ?Identity
	{
		if (!$this->storage->alreadyExists($this->getNamespace())) {
			return null;
		}

		$login = $this->getLogins()->getCurrentLogin();

		return $login === null ? null : $login->getIdentity();
	}

	public function getAuthenticationTime(): Instant
	{
		$login = $this->getLogins()->getCurrentLogin();

		if ($login === null) {
			throw CannotGetAuthenticationTime::create(static::class, __FUNCTION__);
		}

		return $login->getAuthenticationTime();
	}

	public function hasRole(string $role): bool
	{
		$identity = $this->fetchIdentity();

		if ($identity === null) {
			return false;
		}

		return $identity->hasRole($role);
	}

	/**
	 * @throws CannotSetExpiration
	 */
	public function setExpiration(Instant $time): void
	{
		$login = $this->getLogins()->getCurrentLogin();

		if ($login === null) {
			throw CannotSetExpiration::create(static::class, __FUNCTION__);
		}

		$delta = $time->getEpochSecond() - $this->clock->getTime()->getEpochSecond();
		$login->setExpiration(new CurrentExpiration($time, Duration::ofSeconds($delta)));

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

		$now = $this->clock->getTime();

		if ($expiration->getTime()->isBefore($now)) {
			$this->unauthenticate(self::REASON_INACTIVITY, $logins);
		} else {
			$expiration->setTime($now->plusSeconds($expiration->getDelta()->toSeconds()));
		}
	}

	private function checkIdentity(Logins $logins): void
	{
		$login = $logins->getCurrentLogin();

		if ($login === null) {
			return;
		}

		$identity = $this->renewer->renewIdentity($login->getIdentity());

		if ($identity === null) {
			$this->unauthenticate(self::REASON_INVALID_IDENTITY, $logins);
		} else {
			$login->setIdentity($identity);
		}
	}

	/**
	 * @return array<ExpiredLogin>
	 */
	public function getExpiredLogins(): array
	{
		if (!$this->storage->alreadyExists($this->getNamespace())) {
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

	private function addExpiredLogin(ExpiredLogin $login): void
	{
		$logins = $this->getLogins();
		$logins->addExpiredLogin($login);
		$logins->removeOldestExpiredLoginsAboveLimit($this->expiredIdentitiesLimit);
	}

	protected function getLogins(): Logins
	{
		if ($this->logins !== null) {
			return $this->logins;
		}

		$logins = $this->storage->getLogins($this->getNamespace());

		$this->upToDateChecks($logins);

		return $this->logins = $logins;
	}

	private function upToDateChecks(Logins $logins): void
	{
		$this->checkInactivity($logins);
		$this->checkIdentity($logins);
	}

}
