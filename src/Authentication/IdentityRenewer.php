<?php declare(strict_types = 1);

namespace Orisai\Auth\Authentication;

/**
 * @template T of Identity
 */
interface IdentityRenewer
{

	/**
	 * @return T|null
	 */
	public function renewIdentity(Identity $identity): ?Identity;

}
