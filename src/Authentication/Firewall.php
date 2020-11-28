<?php declare(strict_types = 1);

namespace Orisai\Auth\Authentication;

use Brick\DateTime\Instant;
use Orisai\Auth\Authentication\Data\ExpiredLogin;
use Orisai\Auth\Authentication\Exception\CannotAccessIdentity;
use Orisai\Auth\Authentication\Exception\CannotRenewIdentity;
use Orisai\Auth\Authentication\Exception\CannotSetExpiration;

/**
 * @template T of Identity
 */
interface Firewall
{

	public const REASON_MANUAL = 1;
	public const REASON_INACTIVITY = 2;
	public const REASON_INVALID_IDENTITY = 3;

	public const EXPIRED_IDENTITIES_DEFAULT_LIMIT = 3;

	public function isLoggedIn(): bool;

	/**
	 * @param T $identity
	 */
	public function login(Identity $identity): void;

	/**
	 * @param T $identity
	 * @throws CannotRenewIdentity When user is not logged id
	 */
	public function renewIdentity(Identity $identity): void;

	public function logout(): void;

	/**
	 * @return T
	 * @throws CannotAccessIdentity When user is not logged id
	 */
	public function getIdentity(): Identity;

	/**
	 * @throws CannotSetExpiration When expiration is set before user is logged in
	 */
	public function setExpiration(Instant $time): void;

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

	/**
	 * @phpstan-param positive-int $count
	 */
	public function setExpiredIdentitiesLimit(int $count): void;

}
