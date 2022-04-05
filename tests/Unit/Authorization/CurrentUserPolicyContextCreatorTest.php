<?php declare(strict_types = 1);

namespace Tests\Orisai\Auth\Unit\Authorization;

use Orisai\Auth\Authentication\ArrayLoginStorage;
use Orisai\Auth\Authentication\SimpleFirewall;
use Orisai\Auth\Authorization\AuthorizationDataBuilder;
use Orisai\Auth\Authorization\CurrentUserPolicyContextCreator;
use Orisai\Auth\Authorization\PrivilegeAuthorizer;
use Orisai\Auth\Authorization\SimplePolicyManager;
use PHPUnit\Framework\TestCase;
use Tests\Orisai\Auth\Doubles\AlwaysPassIdentityRefresher;

final class CurrentUserPolicyContextCreatorTest extends TestCase
{

	public function test(): void
	{
		$authorizer = new PrivilegeAuthorizer(
			new SimplePolicyManager(),
			(new AuthorizationDataBuilder())->build(),
		);
		$firewall = new SimpleFirewall(
			'a',
			new ArrayLoginStorage(),
			new AlwaysPassIdentityRefresher(),
			$authorizer,
		);

		$creator = new CurrentUserPolicyContextCreator($firewall);
		self::assertSame($authorizer, $creator->create()->getAuthorizer());
	}

}
