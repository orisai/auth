<?php declare(strict_types = 1);

namespace Orisai\Auth\Authentication;

use Brick\DateTime\Instant;
use Orisai\Auth\Authentication\Data\ExpiredLogin;
use Orisai\Auth\Authentication\Exception\NotLoggedIn;

/**
 * @phpstan-template I of Identity
 */
interface Firewall
{

	public const LOGOUT_MANUAL = 1;

	public const LOGOUT_INACTIVITY = 2;

	public const LOGOUT_INVALID_IDENTITY = 3;

	public function isLoggedIn(): bool;

	/**
	 * @phpstan-param I $identity
	 */
	public function login(Identity $identity): void;

	/**
	 * @phpstan-param I $identity
	 * @throws NotLoggedIn
	 */
	public function refreshIdentity(Identity $identity): void;

	public function logout(): void;

	/**
	 * @phpstan-return I
	 * @throws NotLoggedIn
	 */
	public function getIdentity(): Identity;

	public function hasRole(string $role): bool;

	/**
	 * @phpstan-param literal-string $privilege
	 */
	public function isAllowed(string $privilege, ?object $requirements = null, ?DecisionReason &$reason = null): bool;

	/**
	 * @phpstan-param literal-string $privilege
	 */
	public function hasPrivilege(string $privilege): bool;

	/**
	 * @throws NotLoggedIn
	 */
	public function getAuthenticationTime(): Instant;

	/**
	 * @throws NotLoggedIn
	 */
	public function getExpirationTime(): ?Instant;

	/**
	 * @throws NotLoggedIn
	 */
	public function setExpirationTime(Instant $time): void;

	public function removeExpirationTime(): void;

	/**
	 * @return array<ExpiredLogin>
	 */
	public function getExpiredLogins(): array;

	public function getLastExpiredLogin(): ?ExpiredLogin;

	public function removeExpiredLogins(): void;

	/**
	 * @param int|string $id
	 */
	public function removeExpiredLogin($id): void;

	/**
	 * @param int<0, max> $count
	 */
	public function setExpiredIdentitiesLimit(int $count): void;

}
