<?php declare(strict_types = 1);

namespace Tests\Orisai\Auth\Doubles;

use Orisai\Auth\Authorization\PermissionAuthorizer;

final class PermissionAuthorizerCreator
{

	public function create(): PermissionAuthorizer
	{
		return new PermissionAuthorizer();
	}

}
