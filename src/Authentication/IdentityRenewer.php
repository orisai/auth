<?php declare(strict_types = 1);

namespace Orisai\Auth\Authentication;

interface IdentityRenewer
{

	public function renewIdentity(Identity $identity): ?Identity;

}
