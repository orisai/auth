<?php declare(strict_types = 1);

namespace Orisai\Auth\Authentication;

use DateTimeInterface;

interface Firewall
{

	public const REASON_MANUAL = IdentityStorage::REASON_MANUAL;
	public const REASON_INACTIVITY = IdentityStorage::REASON_INACTIVITY;
	public const REASON_INVALID_IDENTITY = IdentityStorage::REASON_INVALID_IDENTITY;

	public function isLoggedIn(): bool;

	public function login(Identity $identity): void;

	public function logout(): void;

	/**
	 * @phpstan-return self::REASON_*|null
	 */
	public function getLogoutReason(): ?int;

	/**
	 * @throws CannotAccessIdentity When user is not logged id
	 */
	public function getIdentity(): Identity;

	public function getExpiredIdentity(): ?Identity;

	public function setExpiration(DateTimeInterface $time): void;

	public function removeExpiration(): void;

}
