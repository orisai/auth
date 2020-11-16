<?php declare(strict_types = 1);

namespace Orisai\Auth\Authentication;

use DateTimeInterface;

/**
 * @phpstan-template T of Identity
 */
interface Firewall
{

	public const REASON_MANUAL = IdentityStorage::REASON_MANUAL;
	public const REASON_INACTIVITY = IdentityStorage::REASON_INACTIVITY;
	public const REASON_INVALID_IDENTITY = IdentityStorage::REASON_INVALID_IDENTITY;

	public function isLoggedIn(): bool;

	/**
	 * @phpstan-param T $identity
	 */
	public function login(Identity $identity): void;

	public function logout(): void;

	/**
	 * @phpstan-return self::REASON_*|null
	 */
	public function getLogoutReason(): ?int;

	/**
	 * @phpstan-return T
	 * @throws CannotAccessIdentity When user is not logged id
	 */
	public function getIdentity(): Identity;

	/**
	 * @phpstan-return T|null
	 */
	public function getExpiredIdentity(): ?Identity;

	public function setExpiration(DateTimeInterface $time): void;

	public function removeExpiration(): void;

}
