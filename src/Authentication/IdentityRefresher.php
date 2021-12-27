<?php declare(strict_types = 1);

namespace Orisai\Auth\Authentication;

use Orisai\Auth\Authentication\Exception\IdentityExpired;

/**
 * @phpstan-template T of Identity
 */
interface IdentityRefresher
{

	/**
	 * @phpstan-return T
	 * @throws IdentityExpired
	 */
	public function refresh(Identity $identity): Identity;

}
