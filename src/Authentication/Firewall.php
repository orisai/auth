<?php declare(strict_types = 1);

namespace Orisai\Auth\Authentication;

use Closure;
use DateTimeImmutable;
use Orisai\Auth\Authentication\Data\ExpiredLogin;
use Orisai\Auth\Authentication\Exception\NotLoggedIn;
use Orisai\Auth\Authorization\AccessEntry;
use Orisai\Auth\Authorization\Authorizer;
use Orisai\Auth\Authorization\MatchAllOfEntries;
use Orisai\Auth\Authorization\MatchAnyOfEntries;

/**
 * @template I of Identity
 */
interface Firewall
{

	public function getNamespace(): string;

	public function isLoggedIn(): bool;

	/**
	 * @param I $identity
	 */
	public function login(Identity $identity): void;

	/**
	 * @param Closure(): void $callback
	 */
	public function addLoginCallback(Closure $callback): void;

	/**
	 * @param I $identity
	 * @throws NotLoggedIn
	 */
	public function refreshIdentity(Identity $identity): void;

	public function logout(): void;

	/**
	 * @param Closure(): void $callback
	 */
	public function addLogoutCallback(Closure $callback): void;

	/**
	 * @return I
	 * @throws NotLoggedIn
	 */
	public function getIdentity(): Identity;

	public function hasRole(string $role): bool;

	/**
	 * @param array{}|null   $entries
	 * @param literal-string $privilege
	 * @param-out list<AccessEntry|MatchAllOfEntries|MatchAnyOfEntries> $entries
	 */
	public function isAllowed(string $privilege, ?object $requirements = null, ?array &$entries = null): bool;

	public function isRoot(): bool;

	/**
	 * @throws NotLoggedIn
	 */
	public function getAuthenticationTime(): DateTimeImmutable;

	/**
	 * @throws NotLoggedIn
	 */
	public function getExpirationTime(): ?DateTimeImmutable;

	/**
	 * @throws NotLoggedIn
	 */
	public function setExpirationTime(DateTimeImmutable $time): void;

	public function removeExpirationTime(): void;

	/**
	 * @return array<int|string, ExpiredLogin>
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
