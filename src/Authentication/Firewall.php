<?php declare(strict_types = 1);

namespace Orisai\Auth\Authentication;

use Brick\DateTime\Instant;
use Closure;
use Orisai\Auth\Authentication\Data\ExpiredLogin;
use Orisai\Auth\Authentication\Exception\NotLoggedIn;
use Orisai\Auth\Authorization\Authorizer;

/**
 * @phpstan-template I of Identity
 */
interface Firewall
{

	public function getNamespace(): string;

	public function isLoggedIn(): bool;

	/**
	 * @phpstan-param I $identity
	 */
	public function login(Identity $identity): void;

	/**
	 * @param Closure(): void $callback
	 */
	public function addLoginCallback(Closure $callback): void;

	/**
	 * @phpstan-param I $identity
	 * @throws NotLoggedIn
	 */
	public function refreshIdentity(Identity $identity): void;

	public function logout(): void;

	/**
	 * @param Closure(): void $callback
	 */
	public function addLogoutCallback(Closure $callback): void;

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

	public function isRoot(): bool;

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

	public function getAuthorizer(): Authorizer;

}
