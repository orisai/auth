<?php declare(strict_types = 1);

namespace Orisai\Auth\Authentication;

use Orisai\Auth\Authentication\Exception\IdentityExpired;

/**
 * @phpstan-template T of Identity
 */
interface IdentityRenewer
{

	/**
	 * @phpstan-return T
	 * @throws IdentityExpired
	 */
	public function renewIdentity(Identity $identity): Identity;

}
