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

	public const REASON_MANUAL = 1;

	public const REASON_INACTIVITY = 2;

	public const REASON_INVALID_IDENTITY = 3;

	public const EXPIRED_IDENTITIES_DEFAULT_LIMIT = 3;

	public function isLoggedIn(): bool;

	/**
	 * @phpstan-param I $identity
	 */
	public function login(Identity $identity): void;

	/**
	 * @phpstan-param I $identity
	 * @throws NotLoggedIn
	 */
	public function renewIdentity(Identity $identity): void;

	public function logout(): void;

	/**
	 * @phpstan-return I
	 * @throws NotLoggedIn
	 */
	public function getIdentity(): Identity;

	public function hasRole(string $role): bool;

	public function isAllowed(string $privilege, ?object $requirements = null): bool;

	public function hasPrivilege(string $privilege): bool;

	/**
	 * @throws NotLoggedIn
	 */
	public function getAuthenticationTime(): Instant;

	/**
	 * @throws NotLoggedIn
	 */
	public function setExpiration(Instant $time): void;

	public function removeExpiration(): void;

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

	public function setExpiredIdentitiesLimit(int $count): void;

}
