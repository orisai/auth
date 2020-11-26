<?php declare(strict_types = 1);

namespace Orisai\Auth\Authentication;

use DateTimeInterface;
use Orisai\Auth\Authentication\Data\ExpiredLogin;
use Orisai\Auth\Authentication\Data\Logins;
use Orisai\Auth\Authentication\Exception\CannotRenewIdentity;
use Orisai\Exceptions\Logic\ShouldNotHappen;

interface LoginStorage
{

	public const REASON_MANUAL = 1;
	public const REASON_INACTIVITY = 2;
	public const REASON_INVALID_IDENTITY = 3;

	public function getLogins(): Logins;

	public function getIdentity(): ?Identity;

	public function login(Identity $identity): void;

	/**
	 * @throws CannotRenewIdentity When user is not logged id
	 */
	public function renewIdentity(Identity $identity): void;

	/**
	 * @phpstan-param self::REASON_* $reason
	 */
	public function logout(int $reason): void;

	/**
	 * @throws ShouldNotHappen When expiration is set before user is logged in and firewall did not check
	 */
	public function setExpiration(DateTimeInterface $time): void;

	public function removeExpiration(): void;

	/**
	 * @return array<ExpiredLogin>
	 */
	public function getExpiredLogins(): array;

	public function removeExpiredLogins(): void;

	/**
	 * @param int|string $id
	 */
	public function removeExpiredLogin($id): void;

	public function setExpiredIdentitiesLimit(int $count): void;

}
