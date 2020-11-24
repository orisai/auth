<?php declare(strict_types = 1);

namespace Orisai\Auth\Authentication;

use DateTimeInterface;

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
		$this->storage->setUnauthenticated($this->storage::REASON_MANUAL);
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
		return $this->storage->getIdentity();
	}

	public function setExpiration(DateTimeInterface $time): void
	{
		$this->storage->setExpiration($time);
	}

	public function removeExpiration(): void
	{
		$this->storage->removeExpiration();
	}

}
