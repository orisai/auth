<?php declare(strict_types = 1);

namespace Orisai\Auth\Authentication;

use DateTimeInterface;
use function is_subclass_of;

/**
 * @template T of Identity
 * @implements Firewall<T>
 */
abstract class BaseFirewall implements Firewall
{

	private IdentityStorage $storage;

	public function __construct(IdentityStorage $storage)
	{
		$this->storage = $storage;
	}

	public function isLoggedIn(): bool
	{
		return $this->storage->isAuthenticated();
	}

	public function login(Identity $identity): void
	{
		$this->storage->setAuthenticated($identity);
	}

	public function logout(): void
	{
		$this->storage->setUnauthenticated();
	}

	public function getLogoutReason(): ?int
	{
		return $this->storage->getLogoutReason();
	}

	/**
	 * @throws CannotAccessIdentity When user is not logged id
	 */
	public function getIdentity(): Identity
	{
		$identity = $this->getExpiredIdentity();

		if ($identity === null || !$this->isLoggedIn()) {
			throw CannotAccessIdentity::create(static::class, __FUNCTION__);
		}

		return $identity;
	}

	public function getExpiredIdentity(): ?Identity
	{
		$class = $this->getIdentityClass();
		$identity = $this->storage->getIdentity();
		if (!is_subclass_of($identity, $class)) {
			// TODO - better method name
			//		- difference between renewal methods should be clear
			//		- storage creates new identity to make it up-to-date and returns null if should log-out
			//		- here is just replaced the outdated Identity calss with new one
			//		- maybe renewer could be moved here and setUnauthenticated could accept reason
			//			- current code with two methods would be redundant
			$identity = $this->identityRenewer->replaceOutdatedClass($class);
		}

		return $identity;
	}

	public function setExpiration(DateTimeInterface $time): void
	{
		$this->storage->setExpiration($time);
	}

	public function removeExpiration(): void
	{
		$this->storage->removeExpiration();
	}

	/**
	 * @phpstan-return class-string<T>
	 */
	abstract protected function getIdentityClass(): string;

}
