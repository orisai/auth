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
use Orisai\Auth\Authentication\Exception\NotLoggedIn;
use Orisai\Auth\Authorization\Authorizer;
use Orisai\Exceptions\Logic\InvalidArgument;
use Orisai\Exceptions\Message;

/**
 * @phpstan-template I of Identity
 * @phpstan-implements Firewall<I>
 */
abstract class BaseFirewall implements Firewall
{

	private LoginStorage $storage;

	/** @phpstan-var IdentityRenewer<I> */
	private IdentityRenewer $renewer;

	private Authorizer $authorizer;

	private Clock $clock;

	protected ?Logins $logins = null;

	private int $expiredIdentitiesLimit = self::EXPIRED_IDENTITIES_DEFAULT_LIMIT;

	/**
	 * @phpstan-param IdentityRenewer<I> $renewer
	 */
	public function __construct(
		LoginStorage $storage,
		IdentityRenewer $renewer,
		Authorizer $authorizer,
		?Clock $clock = null
	)
	{
		$this->storage = $storage;
		$this->renewer = $renewer;
		$this->authorizer = $authorizer;
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
	 * @throws NotLoggedIn
	 */
	public function renewIdentity(Identity $identity): void
	{
		$login = $this->getLogins()->getCurrentLogin();

		if ($login === null) {
			throw NotLoggedIn::create(static::class, __FUNCTION__);
		}

		$login->setIdentity($identity);
	}

	public function logout(): void
	{
		if (!$this->doesStorageAlreadyExist()) {
			return;
		}

		$this->unauthenticate($this->getLogins(), self::REASON_MANUAL, null);
	}

	/**
	 * @phpstan-param self::REASON_* $reason
	 */
	private function unauthenticate(Logins $logins, int $reason, ?string $logoutReasonDescription): void
	{
		$login = $logins->getCurrentLogin();

		if ($login === null) {
			return;
		}

		$logins->removeCurrentLogin();
		$this->addExpiredLogin(new ExpiredLogin($login, $reason, $logoutReasonDescription));

		$this->storage->regenerateSecurityToken($this->getNamespace());
	}

	/**
	 * @throws NotLoggedIn
	 */
	public function getIdentity(): Identity
	{
		$identity = $this->fetchIdentity();

		if ($identity === null) {
			throw NotLoggedIn::create(static::class, __FUNCTION__);
		}

		return $identity;
	}

	protected function fetchCurrentLogin(): ?CurrentLogin
	{
		if (!$this->doesStorageAlreadyExist()) {
			return null;
		}

		return $this->getLogins()->getCurrentLogin();
	}

	protected function fetchIdentity(): ?Identity
	{
		$login = $this->fetchCurrentLogin();

		return $login === null ? null : $login->getIdentity();
	}

	public function getAuthenticationTime(): Instant
	{
		$login = $this->fetchCurrentLogin();

		if ($login === null) {
			throw NotLoggedIn::create(static::class, __FUNCTION__);
		}

		return $login->getAuthenticationTime();
	}

	public function getExpirationTime(): ?Instant
	{
		$login = $this->fetchCurrentLogin();

		if ($login === null) {
			throw NotLoggedIn::create(static::class, __FUNCTION__);
		}

		$expiration = $login->getExpiration();

		return $expiration === null
			? null
			: $expiration->getTime();
	}

	public function hasRole(string $role): bool
	{
		$identity = $this->fetchIdentity();

		if ($identity === null) {
			return false;
		}

		return $identity->hasRole($role);
	}

	public function isAllowed(string $privilege, ?object $requirements = null): bool
	{
		$identity = $this->fetchIdentity();

		if ($identity === null) {
			return false;
		}

		return $this->authorizer->isAllowed($identity, $privilege, $requirements);
	}

	public function hasPrivilege(string $privilege): bool
	{
		$identity = $this->fetchIdentity();

		if ($identity === null) {
			return false;
		}

		return $this->authorizer->hasPrivilege($identity, $privilege);
	}

	/**
	 * @throws NotLoggedIn
	 */
	public function setExpiration(Instant $time): void
	{
		$login = $this->getLogins()->getCurrentLogin();

		if ($login === null) {
			throw NotLoggedIn::create(static::class, __FUNCTION__);
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
		$login = $this->fetchCurrentLogin();

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
			$this->unauthenticate($logins, self::REASON_INACTIVITY, null);
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

		try {
			$identity = $this->renewer->renewIdentity($login->getIdentity());
		} catch (IdentityExpired $exception) {
			$this->unauthenticate($logins, self::REASON_INVALID_IDENTITY, $exception->getLogoutReasonDescription());

			return;
		}

		$login->setIdentity($identity);
	}

	/**
	 * @return array<ExpiredLogin>
	 */
	public function getExpiredLogins(): array
	{
		if (!$this->doesStorageAlreadyExist()) {
			return [];
		}

		return $this->getLogins()->getExpiredLogins();
	}

	public function getLastExpiredLogin(): ?ExpiredLogin
	{
		if (!$this->doesStorageAlreadyExist()) {
			return null;
		}

		return $this->getLogins()->getLastExpiredLogin();
	}

	public function removeExpiredLogins(): void
	{
		if (!$this->doesStorageAlreadyExist()) {
			return;
		}

		$this->getLogins()->removeExpiredLogins();
	}

	/**
	 * @param int|string $id
	 */
	public function removeExpiredLogin($id): void
	{
		if (!$this->doesStorageAlreadyExist()) {
			return;
		}

		$this->getLogins()->removeExpiredLogin($id);
	}

	public function setExpiredIdentitiesLimit(int $count): void
	{
		$this->expiredIdentitiesLimit = $count;

		if ($this->doesStorageAlreadyExist()) {
			$this->getLogins()->removeOldestExpiredLoginsAboveLimit($count);
		}
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

	protected function doesStorageAlreadyExist(): bool
	{
		return $this->storage->alreadyExists($this->getNamespace());
	}

	private function upToDateChecks(Logins $logins): void
	{
		$this->checkInactivity($logins);
		$this->checkIdentity($logins);
	}

}
