<?php declare(strict_types = 1);

namespace Tests\Orisai\Auth\Unit\Authorization;

use Orisai\Auth\Authentication\ArrayLoginStorage;
use Orisai\Auth\Authentication\SimpleFirewall;
use Orisai\Auth\Authorization\AccessEntry;
use Orisai\Auth\Authorization\AuthorizationDataBuilder;
use Orisai\Auth\Authorization\CurrentUserPolicyContext;
use Orisai\Auth\Authorization\PrivilegeAuthorizer;
use Orisai\Auth\Authorization\SimpleAuthorizationDataCreator;
use Orisai\Auth\Authorization\SimplePolicyManager;
use PHPUnit\Framework\TestCase;
use Tests\Orisai\Auth\Doubles\AlwaysPassIdentityRefresher;

final class CurrentUserPolicyContextTest extends TestCase
{

	public function test(): void
	{
		$authorizer = new PrivilegeAuthorizer(
			new SimplePolicyManager(),
			new SimpleAuthorizationDataCreator(new AuthorizationDataBuilder()),
		);
		$firewall = new SimpleFirewall('test', new ArrayLoginStorage(), new AlwaysPassIdentityRefresher(), $authorizer);
		$context = new CurrentUserPolicyContext($firewall);

		self::assertSame($authorizer, $context->getAuthorizer());
		self::assertTrue($context->isCurrentUser());
		self::assertSame([], $context->getExpiredLogins());

		self::assertSame([], $context->getAccessEntries());
		$context->addAccessEntry($entry = new AccessEntry('Message'));
		self::assertSame([$entry], $context->getAccessEntries());
	}

}
