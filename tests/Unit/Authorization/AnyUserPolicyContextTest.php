<?php declare(strict_types = 1);

namespace Tests\Orisai\Auth\Unit\Authorization;

use Orisai\Auth\Authorization\AnyUserPolicyContext;
use Orisai\Auth\Authorization\AuthorizationDataBuilder;
use Orisai\Auth\Authorization\PrivilegeAuthorizer;
use Orisai\Auth\Authorization\SimplePolicyManager;
use PHPUnit\Framework\TestCase;

final class AnyUserPolicyContextTest extends TestCase
{

	public function test(): void
	{
		$authorizer = new PrivilegeAuthorizer(new SimplePolicyManager(), (new AuthorizationDataBuilder())->build());
		$context = new AnyUserPolicyContext($authorizer);

		self::assertSame($authorizer, $context->getAuthorizer());
	}

}
