<?php declare(strict_types = 1);

namespace Tests\Orisai\Auth\Unit\Authorization;

use Orisai\Auth\Authentication\ArrayLoginStorage;
use Orisai\Auth\Authentication\SimpleFirewall;
use Orisai\Auth\Authorization\AuthorizationDataBuilder;
use Orisai\Auth\Authorization\CurrentUserPolicyContext;
use Orisai\Auth\Authorization\PrivilegeAuthorizer;
use Orisai\Auth\Authorization\SimplePolicyManager;
use PHPUnit\Framework\TestCase;
use Tests\Orisai\Auth\Doubles\AlwaysPassIdentityRenewer;

final class CurrentUserPolicyContextTest extends TestCase
{

	public function test(): void
	{
		$authorizer = new PrivilegeAuthorizer(new SimplePolicyManager(), (new AuthorizationDataBuilder())->build());
		$firewall = new SimpleFirewall('test', new ArrayLoginStorage(), new AlwaysPassIdentityRenewer(), $authorizer);
		$context = new CurrentUserPolicyContext($authorizer, $firewall);

		self::assertSame($authorizer, $context->getAuthorizer());
		self::assertSame([], $context->getExpiredLogins());
	}

}