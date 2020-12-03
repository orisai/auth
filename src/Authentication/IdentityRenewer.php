<?php declare(strict_types = 1);

namespace Orisai\Auth\Authentication;

/**
 * @phpstan-template T of Identity
 */
interface IdentityRenewer
{

	/**
	 * @phpstan-return T|null
	 */
	public function renewIdentity(Identity $identity): ?Identity;

}
