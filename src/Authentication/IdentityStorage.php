<?php declare(strict_types = 1);

namespace Orisai\Auth\Authentication;

use DateTimeInterface;

interface IdentityStorage
{

	public const REASON_MANUAL = 1;
	public const REASON_INACTIVITY = 2;
	public const REASON_INVALID_IDENTITY = 3;

	public function getIdentity(): ?Identity;

	public function setAuthenticated(Identity $identity): void;

	public function setUnauthenticated(): void;

	public function isAuthenticated(): bool;

	/**
	 * @phpstan-return self::REASON_*|null
	 */
	public function getLogoutReason(): ?int;

	public function setExpiration(DateTimeInterface $time): void;

	public function removeExpiration(): void;

}
