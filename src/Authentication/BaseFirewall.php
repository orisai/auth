<?php declare(strict_types = 1);

namespace Orisai\Auth\Authentication;

use Closure;
use DateTimeImmutable;
use Orisai\Auth\Authentication\Data\CurrentExpiration;
use Orisai\Auth\Authentication\Data\CurrentLogin;
use Orisai\Auth\Authentication\Data\ExpiredLogin;
use Orisai\Auth\Authentication\Data\Logins;
use Orisai\Auth\Authentication\Exception\IdentityExpired;
use Orisai\Auth\Authentication\Exception\NotLoggedIn;
use Orisai\Auth\Authorization\AccessEntry;
use Orisai\Auth\Authorization\Authorizer;
use Orisai\Auth\Authorization\CurrentUserPolicyContextCreator;
use Orisai\Clock\SystemClock;
use Orisai\Exceptions\Logic\InvalidArgument;
use Orisai\Exceptions\Message;
use Psr\Clock\ClockInterface;

/**
 * @phpstan-template I of Identity
 * @phpstan-implements Firewall<I>
 */
abstract class BaseFirewall implements Firewall
{

	private LoginStorage $storage;

	/** @phpstan-var IdentityRefresher<I> */
	private IdentityRefresher $refresher;

	private Authorizer $authorizer;

	private ClockInterface $clock;

	protected ?Logins $logins = null;

	/** @var int<0, max> */
	private int $expiredIdentitiesLimit = 3;

	/** @var array<Closure(): void> */
	private array $onLogin = [];

	/** @var array<Closure(): void> */
	private array $onLogout = [];

	private CurrentUserPolicyContextCreator $contextCreator;

	/**
	 * @phpstan-param IdentityRefresher<I> $refresher
	 */
	public function __construct(
		LoginStorage $storage,
		IdentityRefresher $refresher,
		Authorizer $authorizer,
		?ClockInterface $clock = null
	)
	{
		$this->storage = $storage;
		$this->refresher = $refresher;
		$this->authorizer = $authorizer;
		$this->clock = $clock ?? new SystemClock();
		$this->contextCreator = new CurrentUserPolicyContextCreator($this);
	}

	abstract public function getNamespace(): string;

	public function isLoggedIn(): bool
	{
		return $this->fetchIdentity() !== null;
	}

	public function login(Identity $identity): void
	{
		$logins = $this->getLogins();

		$this->unauthenticate($logins, LogoutCode::manual(), null);
		$logins->setCurrentLogin(new CurrentLogin($identity, $this->clock->now()));

		foreach ($this->onLogin as $cb) {
			$cb();
		}

		$this->storage->regenerateSecurityToken($this->getNamespace());
	}

	public function addLoginCallback(Closure $callback): void
	{
		$this->onLogin[] = $callback;
	}

	public function refreshIdentity(Identity $identity): void
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

		$this->unauthenticate($this->getLogins(), LogoutCode::manual(), null);
	}

	public function addLogoutCallback(Closure $callback): void
	{
		$this->onLogout[] = $callback;
	}

	private function unauthenticate(Logins $logins, LogoutCode $logoutCode, ?DecisionReason $logoutReason): void
	{
		$login = $logins->getCurrentLogin();

		if ($login === null) {
			return;
		}

		$logins->removeCurrentLogin();
		$this->addExpiredLogin(new ExpiredLogin($login, $logoutCode, $logoutReason));

		foreach ($this->onLogout as $cb) {
			$cb();
		}

		$this->storage->regenerateSecurityToken($this->getNamespace());
	}

	public function getIdentity(): Identity
	{
		$identity = $this->fetchIdentity();

		if ($identity === null) {
			throw NotLoggedIn::create(static::class, __FUNCTION__);
		}

		return $identity;
	}

	private function fetchCurrentLogin(): ?CurrentLogin
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

	public function getAuthenticationTime(): DateTimeImmutable
	{
		$login = $this->fetchCurrentLogin();

		if ($login === null) {
			throw NotLoggedIn::create(static::class, __FUNCTION__);
		}

		return $login->getAuthenticationTime();
	}

	public function getExpirationTime(): ?DateTimeImmutable
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

	public function isAllowed(string $privilege, ?object $requirements = null, ?AccessEntry &$entry = null): bool
	{
		return $this->authorizer->isAllowed(
			$this->fetchIdentity(),
			$privilege,
			$requirements,
			$entry,
			$this->contextCreator,
		);
	}

	public function isRoot(): bool
	{
		$identity = $this->fetchIdentity();

		if ($identity === null) {
			return false;
		}

		return $this->authorizer->isRoot($identity);
	}

	/**
	 * @throws NotLoggedIn
	 */
	public function setExpirationTime(DateTimeImmutable $time): void
	{
		$login = $this->getLogins()->getCurrentLogin();

		if ($login === null) {
			throw NotLoggedIn::create(static::class, __FUNCTION__);
		}

		$delta = $time->getTimestamp() - $this->clock->now()->getTimestamp();
		$login->setExpiration(new CurrentExpiration($time, $delta));

		if ($delta <= 0) {
			$message = Message::create()
				->withContext('Trying to set login expiration time.')
				->withProblem('Expiration time is lower than current time.')
				->withSolution('Choose expiration time which is in future.');

			throw InvalidArgument::create()
				->withMessage($message);
		}
	}

	public function removeExpirationTime(): void
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

		$now = $this->clock->now();

		if ($expiration->getTime() < $now) {
			$this->unauthenticate($logins, LogoutCode::inactivity(), null);
		} else {
			$expiration->setTime($now->modify("+{$expiration->getDelta()} seconds"));
		}
	}

	private function checkIdentity(Logins $logins): void
	{
		$login = $logins->getCurrentLogin();

		if ($login === null) {
			return;
		}

		try {
			$identity = $this->refresher->refresh($login->getIdentity());
		} catch (IdentityExpired $exception) {
			$this->unauthenticate($logins, LogoutCode::invalidIdentity(), $exception->getLogoutReason());

			return;
		}

		$login->setIdentity($identity);
	}

	/**
	 * {@inheritDoc}
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
	 * {@inheritDoc}
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

	private function doesStorageAlreadyExist(): bool
	{
		return $this->storage->alreadyExists($this->getNamespace());
	}

	private function upToDateChecks(Logins $logins): void
	{
		$this->checkInactivity($logins);
		$this->checkIdentity($logins);
	}

	public function getAuthorizer(): Authorizer
	{
		return $this->authorizer;
	}

}
