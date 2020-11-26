<?php declare(strict_types = 1);

namespace Orisai\Auth\Authentication;

use DateTimeInterface;
use Orisai\Auth\Authentication\Data\ExpiredLogin;
use Orisai\Auth\Authentication\Exception\CannotAccessIdentity;
use Orisai\Auth\Authentication\Exception\CannotRenewIdentity;
use Orisai\Auth\Authentication\Exception\CannotSetExpiration;

abstract class BaseFirewall implements Firewall
{

	private LoginStorage $storage;

	public function __construct(LoginStorage $storage)
	{
		$this->storage = $storage;
	}

	public function isLoggedIn(): bool
	{
		return $this->storage->getIdentity() !== null;
	}

	public function login(Identity $identity): void
	{
		$this->storage->login($identity);
	}

	/**
	 * @throws CannotRenewIdentity When user is not logged id
	 */
	public function renewIdentity(Identity $identity): void
	{
		if (!$this->isLoggedIn()) {
			throw CannotRenewIdentity::create(static::class, __FUNCTION__);
		}

		$this->storage->renewIdentity($identity);
	}

	public function logout(): void
	{
		$this->storage->logout($this->storage::REASON_MANUAL);
	}

	/**
	 * @throws CannotAccessIdentity When user is not logged id
	 */
	public function getIdentity(): Identity
	{
		$identity = $this->storage->getIdentity();

		if ($identity === null || !$this->isLoggedIn()) {
			throw CannotAccessIdentity::create(static::class, __FUNCTION__);
		}

		return $identity;
	}

	/**
	 * @throws CannotSetExpiration When expiration is set before user is logged in
	 */
	public function setExpiration(DateTimeInterface $time): void
	{
		if (!$this->isLoggedIn()) {
			throw CannotSetExpiration::create(static::class, __FUNCTION__);
		}

		$this->storage->setExpiration($time);
	}

	public function removeExpiration(): void
	{
		$this->storage->removeExpiration();
	}

	/**
	 * @return array<ExpiredLogin>
	 */
	public function getExpiredLogins(): array
	{
		return $this->storage->getExpiredLogins();
	}

	public function removeExpiredLogins(): void
	{
		$this->storage->removeExpiredLogins();
	}

	/**
	 * @param int|string $id
	 */
	public function removeExpiredLogin($id): void
	{
		$this->storage->removeExpiredLogin($id);
	}

	public function setExpiredIdentitiesLimit(int $count): void
	{
		$this->storage->setExpiredIdentitiesLimit($count);
	}

}
