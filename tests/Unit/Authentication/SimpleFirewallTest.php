<?php declare(strict_types = 1);

namespace Tests\Orisai\Auth\Unit\Authentication;

use Orisai\Auth\Authentication\ArrayLoginStorage;
use Orisai\Auth\Authentication\IntIdentity;
use Orisai\Auth\Authentication\SimpleFirewall;
use Orisai\Auth\Authorization\AuthorizationDataBuilder;
use Orisai\Auth\Authorization\PrivilegeAuthorizer;
use Orisai\Auth\Authorization\SimplePolicyManager;
use PHPUnit\Framework\TestCase;
use Tests\Orisai\Auth\Doubles\AlwaysPassIdentityRefresher;

final class SimpleFirewallTest extends TestCase
{

	public function test(): void
	{
		$storage = new ArrayLoginStorage();
		$firewall = new SimpleFirewall(
			'simple',
			$storage,
			new AlwaysPassIdentityRefresher(),
			new PrivilegeAuthorizer(
				new SimplePolicyManager(),
				(new AuthorizationDataBuilder())->build(),
			),
			null,
		);

		self::assertFalse($storage->alreadyExists('simple'));
		$firewall->login(new IntIdentity(123, []));
		self::assertTrue($storage->alreadyExists('simple'));
	}

}
