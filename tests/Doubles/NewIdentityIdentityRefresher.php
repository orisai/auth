<?php declare(strict_types = 1);

namespace Tests\Orisai\Auth\Doubles;

use Orisai\Auth\Authentication\Identity;
use Orisai\Auth\Authentication\IdentityRefresher;

/**
 * @phpstan-implements IdentityRefresher<Identity>
 */
final class NewIdentityIdentityRefresher implements IdentityRefresher
{

	private Identity $identity;

	public function __construct(Identity $identity)
	{
		$this->identity = $identity;
	}

	public function refresh(Identity $identity): Identity
	{
		return $this->identity;
	}

}
