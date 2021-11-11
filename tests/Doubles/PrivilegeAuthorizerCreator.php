<?php declare(strict_types = 1);

namespace Tests\Orisai\Auth\Doubles;

use Orisai\Auth\Authorization\AuthorizationDataBuilder;
use Orisai\Auth\Authorization\PolicyManager;
use Orisai\Auth\Authorization\PrivilegeAuthorizer;

final class PrivilegeAuthorizerCreator
{

	public function create(PolicyManager $policyManager, AuthorizationDataBuilder $builder): PrivilegeAuthorizer
	{
		return new PrivilegeAuthorizer($policyManager, $builder->build());
	}

}
