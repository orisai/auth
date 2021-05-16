<?php declare(strict_types = 1);

namespace Tests\Orisai\Auth\Doubles;

use Orisai\Auth\Authentication\Identity;
use Orisai\Auth\Authentication\IdentityRenewer;

/**
 * @phpstan-implements IdentityRenewer<Identity>
 */
final class NewIdentityIdentityRenewer implements IdentityRenewer
{

	private Identity $identity;

	public function __construct(Identity $identity)
	{
		$this->identity = $identity;
	}

	public function renewIdentity(Identity $identity): Identity
	{
		return $this->identity;
	}

}
