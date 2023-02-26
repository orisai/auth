<?php declare(strict_types = 1);

namespace Orisai\Auth\Authorization;

use Orisai\Auth\Authentication\Data\ExpiredLogin;

/**
 * @readonly
 */
interface PolicyContext
{

	public function isCurrentUser(): bool;

	public function getAuthorizer(): Authorizer;

	/**
	 * @return array<ExpiredLogin>
	 */
	public function getExpiredLogins(): array;

	public function getLastExpiredLogin(): ?ExpiredLogin;

}
