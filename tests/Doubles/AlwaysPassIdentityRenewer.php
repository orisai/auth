<?php declare(strict_types = 1);

namespace Tests\Orisai\Auth\Doubles;

use Orisai\Auth\Authentication\Identity;
use Orisai\Auth\Authentication\IdentityRenewer;

final class AlwaysPassIdentityRenewer implements IdentityRenewer
{

	public function renewIdentity(Identity $identity): ?Identity
	{
		return $identity;
	}

}
