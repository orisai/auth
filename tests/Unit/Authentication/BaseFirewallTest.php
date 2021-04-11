<?php declare(strict_types = 1);

namespace Tests\Orisai\Auth\Unit\Authentication;

use Brick\DateTime\Clock\FixedClock;
use Brick\DateTime\Instant;
use Orisai\Auth\Authentication\ArrayLoginStorage;
use Orisai\Auth\Authentication\Exception\NotLoggedIn;
use Orisai\Auth\Authentication\IntIdentity;
use Orisai\Auth\Authentication\StringIdentity;
use Orisai\Auth\Authorization\Authorizer;
use Orisai\Auth\Authorization\PrivilegeAuthorizer;
use Orisai\Exceptions\Logic\InvalidArgument;
use Orisai\Exceptions\Logic\InvalidState;
use PHPUnit\Framework\TestCase;
use Tests\Orisai\Auth\Doubles\AlwaysPassIdentityRenewer;
use Tests\Orisai\Auth\Doubles\Article;
use Tests\Orisai\Auth\Doubles\ArticleEditOwnedPolicy;
use Tests\Orisai\Auth\Doubles\ArticleEditPolicy;
use Tests\Orisai\Auth\Doubles\NeverPassIdentityRenewer;
use Tests\Orisai\Auth\Doubles\NeverPassPolicy;
use Tests\Orisai\Auth\Doubles\NewIdentityIdentityRenewer;
use Tests\Orisai\Auth\Doubles\TestingFirewall;
use Tests\Orisai\Auth\Doubles\User;
use Tests\Orisai\Auth\Doubles\UserAwareFirewall;
use Tests\Orisai\Auth\Doubles\UserGetter;
use function array_keys;

final class BaseFirewallTest extends TestCase
{

	private function renewer(): AlwaysPassIdentityRenewer
	{
		return new AlwaysPassIdentityRenewer();
	}

	private function authorizer(): PrivilegeAuthorizer
	{
		return new PrivilegeAuthorizer();
	}

	public function testBase(): void
	{
		$storage = new ArrayLoginStorage();
		$firewall = new TestingFirewall($storage, $this->renewer(), $this->authorizer());
		$identity = new IntIdentity(123, []);

		self::assertFalse($firewall->isLoggedIn());
		self::assertSame([], $firewall->getExpiredLogins());

		$firewall->login($identity);
		self::assertTrue($firewall->isLoggedIn());
		self::assertSame($identity, $firewall->getIdentity());
		self::assertSame([], $firewall->getExpiredLogins());

		$firewall->logout();
		self::assertFalse($firewall->isLoggedIn());

		$expired = $firewall->getExpiredLogins()[123];
		self::assertSame($identity, $expired->getIdentity());
		self::assertSame($firewall::REASON_MANUAL, $expired->getLogoutReason());

		$this->expectException(NotLoggedIn::class);
		$firewall->getIdentity();
	}

	public function testSeparateNamespaces(): void
	{
		$storage = new ArrayLoginStorage();
		$identity = new IntIdentity(123, []);

		$firewall1 = new TestingFirewall($storage, $this->renewer(), $this->authorizer(), null, 'one');
		$firewall2 = new TestingFirewall($storage, $this->renewer(), $this->authorizer(), null, 'two');

		self::assertFalse($storage->alreadyExists('one'));
		self::assertFalse($storage->alreadyExists('two'));

		$firewall1->login($identity);
		self::assertTrue($storage->alreadyExists('one'));
		self::assertFalse($storage->alreadyExists('two'));

		$firewall2->login($identity);
		self::assertTrue($storage->alreadyExists('one'));
		self::assertTrue($storage->alreadyExists('two'));

		self::assertSame($firewall1->getIdentity(), $firewall2->getIdentity());

		$newIdentity = new IntIdentity(456, []);
		$firewall1->login($newIdentity);

		self::assertSame($newIdentity, $firewall1->getIdentity());
		self::assertSame($identity, $firewall2->getIdentity());
	}

	public function testIdentityClassUpdate(): void
	{
		$originalIdentity = new IntIdentity(123, []);
		$renewedIdentity = new StringIdentity('string', []);

		$storage = new ArrayLoginStorage();
		$firewall = new TestingFirewall(
			$storage,
			new NewIdentityIdentityRenewer($renewedIdentity),
			$this->authorizer(),
		);

		$firewall->login($originalIdentity);
		$firewall->resetLoginsChecks();
		self::assertSame($renewedIdentity, $firewall->getLogins()->getCurrentLogin()->getIdentity());
	}

	public function testHasRole(): void
	{
		$identity = new IntIdentity(123, ['foo']);

		$storage = new ArrayLoginStorage();
		$firewall = new TestingFirewall($storage, $this->renewer(), $this->authorizer());

		self::assertFalse($firewall->hasRole('foo'));

		$firewall->login($identity);
		self::assertTrue($firewall->hasRole('foo'));
		self::assertFalse($firewall->hasRole('bar'));
	}

	public function testExpiredIdentities(): void
	{
		$storage = new ArrayLoginStorage();
		$firewall = new TestingFirewall($storage, $this->renewer(), $this->authorizer());
		$firewall->setExpiredIdentitiesLimit(3);
		$identity1 = new IntIdentity(1, []);

		$firewall->login($identity1);
		self::assertSame([], $firewall->getExpiredLogins());

		$firewall->logout();
		self::assertSame([1], array_keys($firewall->getExpiredLogins()));

		$firewall->login($identity1);
		self::assertSame([], $firewall->getExpiredLogins());

		$identity2 = new StringIdentity('second', []);
		$firewall->login($identity2);
		self::assertSame([1], array_keys($firewall->getExpiredLogins()));

		$firewall->logout();
		self::assertSame([1, 'second'], array_keys($firewall->getExpiredLogins()));

		$identity3 = new IntIdentity(3, []);
		$firewall->login($identity3);
		$firewall->login($identity2);
		$firewall->logout();
		self::assertSame([1, 3, 'second'], array_keys($firewall->getExpiredLogins()));

		// logout removes logins above limit
		$identity4 = new IntIdentity(4, []);
		$firewall->login($identity4);
		$firewall->logout();
		self::assertSame([3, 'second', 4], array_keys($firewall->getExpiredLogins()));

		// new login also removes logins above limit
		$firewall->login($identity1);
		$identity5 = new StringIdentity('fifth', []);
		$firewall->login($identity5);
		self::assertSame(['second', 4, 1], array_keys($firewall->getExpiredLogins()));

		// Remove expired login with specific ID
		$firewall->removeExpiredLogin(4);
		self::assertSame(['second', 1], array_keys($firewall->getExpiredLogins()));

		// Remove expired logins above limit
		$firewall->setExpiredIdentitiesLimit(1);
		self::assertSame([1], array_keys($firewall->getExpiredLogins()));

		// Remove all expired logins
		$firewall->removeExpiredLogins();
		self::assertSame([], $firewall->getExpiredLogins());
	}

	public function testManualRenewIdentity(): void
	{
		$storage = new ArrayLoginStorage();
		$firewall = new TestingFirewall($storage, $this->renewer(), $this->authorizer());
		$identity = new IntIdentity(123, []);

		$firewall->login($identity);
		self::assertSame($identity, $firewall->getIdentity());

		$firewall->renewIdentity($identity);
		self::assertSame($identity, $firewall->getIdentity());

		$newIdentity = new IntIdentity(456, []);
		$firewall->renewIdentity($newIdentity);
		self::assertSame($newIdentity, $firewall->getIdentity());
	}

	public function testManualRenewIdentityFailure(): void
	{
		$storage = new ArrayLoginStorage();
		$firewall = new TestingFirewall($storage, $this->renewer(), $this->authorizer());
		$identity = new IntIdentity(123, []);

		$this->expectException(NotLoggedIn::class);
		$this->expectExceptionMessage(<<<'MSG'
Context: Calling Tests\Orisai\Auth\Doubles\TestingFirewall->renewIdentity().
Problem: User is not logged in firewall.
Solution: Login with TestingFirewall->login($identity) or check with
          TestingFirewall->isLoggedIn().
MSG);

		$firewall->renewIdentity($identity);
	}

	public function testRenewerSameIdentity(): void
	{
		$identity = new IntIdentity(123, []);

		$storage = new ArrayLoginStorage();
		$renewer = new AlwaysPassIdentityRenewer();
		$firewall = new TestingFirewall($storage, $renewer, $this->authorizer());

		$firewall->login($identity);
		self::assertSame($identity, $firewall->getIdentity());
		self::assertSame([], $firewall->getExpiredLogins());

		$firewall->resetLoginsChecks();

		self::assertSame($identity, $firewall->getIdentity());
		self::assertSame([], $firewall->getExpiredLogins());
	}

	public function testRenewerNewIdentity(): void
	{
		$originalIdentity = new IntIdentity(123, []);
		$newIdentity = new IntIdentity(456, []);

		$storage = new ArrayLoginStorage();
		$renewer = new NewIdentityIdentityRenewer($newIdentity);
		$firewall = new TestingFirewall($storage, $renewer, $this->authorizer());

		$firewall->login($originalIdentity);
		self::assertSame($originalIdentity, $firewall->getIdentity());
		self::assertSame([], $firewall->getExpiredLogins());

		$firewall->resetLoginsChecks();

		self::assertSame($newIdentity, $firewall->getIdentity());
		self::assertSame([], $firewall->getExpiredLogins());
	}

	public function testRenewerRemovedIdentity(): void
	{
		$identity = new IntIdentity(123, []);

		$storage = new ArrayLoginStorage();
		$renewer = new NeverPassIdentityRenewer();
		$firewall = new TestingFirewall($storage, $renewer, $this->authorizer());

		$firewall->login($identity);
		self::assertSame($identity, $firewall->getIdentity());
		self::assertSame([], $firewall->getExpiredLogins());

		$firewall->resetLoginsChecks();

		$expired = $firewall->getExpiredLogins()[123];
		self::assertSame($identity, $expired->getIdentity());
		self::assertSame($firewall::REASON_INVALID_IDENTITY, $expired->getLogoutReason());
	}

	public function testTimeExpiredIdentity(): void
	{
		$clock = new FixedClock(Instant::now());
		$storage = new ArrayLoginStorage();
		$firewall = new TestingFirewall($storage, $this->renewer(), $this->authorizer(), $clock);
		$identity = new IntIdentity(123, []);

		$firewall->login($identity);
		$firewall->setExpiration(Instant::now()->plusSeconds(1));
		self::assertSame($identity, $firewall->getIdentity());

		$clock->move(2);
		$firewall->resetLoginsChecks();

		self::assertFalse($firewall->isLoggedIn());
		$expired = $firewall->getExpiredLogins()[123];
		self::assertSame($identity, $expired->getIdentity());
		self::assertSame($firewall::REASON_INACTIVITY, $expired->getLogoutReason());

		$firewall->login($identity);
		self::assertTrue($firewall->isLoggedIn());
		self::assertSame($identity, $firewall->getIdentity());
		self::assertSame([], $firewall->getExpiredLogins());
	}

	public function testNotTimeExpiredIdentity(): void
	{
		$storage = new ArrayLoginStorage();
		$firewall = new TestingFirewall($storage, $this->renewer(), $this->authorizer());
		$identity = new IntIdentity(123, []);

		$firewall->login($identity);
		$firewall->setExpiration(Instant::now()->plusMinutes(10));
		self::assertSame($identity, $firewall->getIdentity());

		$firewall->resetLoginsChecks();

		self::assertSame($identity, $firewall->getIdentity());
		self::assertSame([], $firewall->getExpiredLogins());
	}

	public function testRemovedTimeExpiration(): void
	{
		$clock = new FixedClock(Instant::now());
		$storage = new ArrayLoginStorage();
		$firewall = new TestingFirewall($storage, $this->renewer(), $this->authorizer(), $clock);
		$identity = new IntIdentity(123, []);

		$firewall->login($identity);
		$firewall->setExpiration(Instant::now()->plusSeconds(1));
		$firewall->removeExpiration();
		self::assertSame($identity, $firewall->getIdentity());

		$clock->move(2);
		$firewall->resetLoginsChecks();

		self::assertSame($identity, $firewall->getIdentity());
		self::assertSame([], $firewall->getExpiredLogins());
	}

	public function testExpirationTimeInThePast(): void
	{
		$storage = new ArrayLoginStorage();
		$firewall = new TestingFirewall($storage, $this->renewer(), $this->authorizer());
		$identity = new IntIdentity(123, []);

		$firewall->login($identity);

		$this->expectException(InvalidArgument::class);
		$this->expectExceptionMessage(<<<'MSG'
Context: Trying to set login expiration time.
Problem: Expiration time is lower than current time.
Solution: Choose expiration time which is in future.
MSG);

		$firewall->setExpiration(Instant::now()->minusSeconds(10));
	}

	public function testExpirationCannotBeSet(): void
	{
		$storage = new ArrayLoginStorage();
		$firewall = new TestingFirewall($storage, $this->renewer(), $this->authorizer());

		$this->expectException(NotLoggedIn::class);
		$this->expectExceptionMessage(<<<'MSG'
Context: Calling Tests\Orisai\Auth\Doubles\TestingFirewall->setExpiration().
Problem: User is not logged in firewall.
Solution: Login with TestingFirewall->login($identity) or check with
          TestingFirewall->isLoggedIn().
MSG);

		$firewall->setExpiration(Instant::now()->minusSeconds(10));
	}

	public function testNotLoggedInGetIdentity(): void
	{
		$storage = new ArrayLoginStorage();
		$firewall = new TestingFirewall($storage, $this->renewer(), $this->authorizer());

		$this->expectException(NotLoggedIn::class);
		$this->expectExceptionMessage(<<<'MSG'
Context: Calling Tests\Orisai\Auth\Doubles\TestingFirewall->getIdentity().
Problem: User is not logged in firewall.
Solution: Login with TestingFirewall->login($identity) or check with
          TestingFirewall->isLoggedIn().
MSG);

		$firewall->getIdentity();
	}

	public function testGetAuthenticationTime(): void
	{
		$storage = new ArrayLoginStorage();
		$firewall = new TestingFirewall(
			$storage,
			$this->renewer(),
			$this->authorizer(),
			new FixedClock(Instant::of(1)),
		);

		$identity = new IntIdentity(123, []);
		$firewall->login($identity);
		self::assertSame(1, $firewall->getAuthenticationTime()->getEpochSecond());
	}

	public function testNotLoggedInGetAuthTime(): void
	{
		$storage = new ArrayLoginStorage();
		$firewall = new TestingFirewall($storage, $this->renewer(), $this->authorizer());

		$this->expectException(NotLoggedIn::class);
		$this->expectExceptionMessage(<<<'MSG'
Context: Calling
         Tests\Orisai\Auth\Doubles\TestingFirewall->getAuthenticationTime().
Problem: User is not logged in firewall.
Solution: Login with TestingFirewall->login($identity) or check with
          TestingFirewall->isLoggedIn().
MSG);

		$firewall->getAuthenticationTime();
	}

	/**
	 * Prevents errors like "headers already sent" when storage uses session
	 * and firewall is used for read after headers were sent
	 */
	public function testMethodsDoesNotUnnecessaryTriggerStorageCreation(): void
	{
		$storage = new ArrayLoginStorage();
		$namespace = 'test';
		$firewall = new TestingFirewall($storage, $this->renewer(), $this->authorizer(), null, $namespace);

		self::assertFalse($storage->alreadyExists($namespace));

		try {
			$firewall->getIdentity();
		} catch (NotLoggedIn $exception) {
			// Just to test storage creation
		}

		self::assertFalse($storage->alreadyExists($namespace));

		try {
			$firewall->getAuthenticationTime();
		} catch (NotLoggedIn $exception) {
			// Just to test storage creation
		}

		self::assertFalse($storage->alreadyExists($namespace));

		self::assertSame([], $firewall->getExpiredLogins());
		self::assertFalse($storage->alreadyExists($namespace));

		self::assertFalse($firewall->hasRole('any'));
		self::assertFalse($storage->alreadyExists($namespace));

		self::assertFalse($firewall->isAllowed('any'));
		self::assertFalse($storage->alreadyExists($namespace));

		$firewall->logout();
		self::assertFalse($storage->alreadyExists($namespace));

		$firewall->removeExpiration();
		self::assertFalse($storage->alreadyExists($namespace));

		$firewall->removeExpiredLogins();
		self::assertFalse($storage->alreadyExists($namespace));

		$firewall->removeExpiredLogin('1234');
		self::assertFalse($storage->alreadyExists($namespace));

		$firewall->setExpiredIdentitiesLimit(5);
		self::assertFalse($storage->alreadyExists($namespace));
	}

	public function testIsAllowed(): void
	{
		$storage = new ArrayLoginStorage();
		$authorizer = new PrivilegeAuthorizer();
		$firewall = new TestingFirewall($storage, $this->renewer(), $authorizer, null, 'test');

		$authorizer->addPrivilege('admin');
		$authorizer->addPrivilege('front');

		$authorizer->addRole('guest');

		$authorizer->allow('guest', 'front');

		self::assertFalse($firewall->isAllowed('front'));
		self::assertFalse($firewall->hasPrivilege('front'));
		self::assertFalse($firewall->isAllowed('admin'));
		self::assertFalse($firewall->hasPrivilege('admin'));

		$identity = new IntIdentity(1, ['guest']);
		$firewall->login($identity);

		self::assertTrue($firewall->isAllowed('front'));
		self::assertTrue($firewall->hasPrivilege('front'));
		self::assertFalse($firewall->isAllowed('admin'));
		self::assertFalse($firewall->hasPrivilege('admin'));
	}

	/**
	 * @doesNotPerformAssertions
	 */
	public function testRemovalMethodsSoftFail(): void
	{
		$storage = new ArrayLoginStorage();
		$firewall = new TestingFirewall($storage, $this->renewer(), $this->authorizer());

		$firewall->logout();
		$firewall->removeExpiration();
		$firewall->removeExpiredLogin(123);
		$firewall->removeExpiredLogins();
	}

	public function testAddPolicy(): void
	{
		$authorizer = $this->authorizer();
		$firewall = new UserAwareFirewall(new UserGetter(), new ArrayLoginStorage(), $this->renewer(), $authorizer);

		$authorizer->addPrivilege('article.edit');
		$firewall->addPolicy(ArticleEditPolicy::class);

		$this->expectException(InvalidState::class);
		$this->expectExceptionMessage(<<<'MSG'
Context: Trying to add policy of type
         Tests\Orisai\Auth\Doubles\ArticleEditOwnedPolicy via
         Tests\Orisai\Auth\Doubles\UserAwareFirewall->addPolicy().
Problem: Policies privilege article.edit.owned is not known by underlying
         authorizer (type of Orisai\Auth\Authorization\PrivilegeAuthorizer).
Solution: Add privilege to authorizer first.
MSG);

		$firewall->addPolicy(ArticleEditOwnedPolicy::class);
	}

	public function testIsAllowedUnknownPolicy(): void
	{
		$authorizer = $this->authorizer();
		$firewall = new UserAwareFirewall(new UserGetter(), new ArrayLoginStorage(), $this->renewer(), $authorizer);

		$this->expectException(InvalidState::class);
		$this->expectExceptionMessage(<<<'MSG'
Context: Trying to check policy of type
         Tests\Orisai\Auth\Doubles\ArticleEditOwnedPolicy via
         Tests\Orisai\Auth\Doubles\UserAwareFirewall->isAllowed().
Problem: Policy is not registered by UserAwareFirewall.
Solution: Register policy via UserAwareFirewall->addPolicy() first.
MSG);

		$firewall->isAllowed(new ArticleEditOwnedPolicy(new Article(new User(1))));
	}

	public function testIsAllowedRequiresPolicy(): void
	{
		$authorizer = $this->authorizer();
		$firewall = new UserAwareFirewall(new UserGetter(), new ArrayLoginStorage(), $this->renewer(), $authorizer);

		self::assertFalse($firewall->isAllowed('article.edit'));

		$authorizer->addPrivilege('article.edit');
		$firewall->addPolicy(ArticleEditPolicy::class);

		$this->expectException(InvalidArgument::class);
		$this->expectExceptionMessage(<<<'MSG'
Context: Trying to check privilege article.edit via
         Tests\Orisai\Auth\Doubles\UserAwareFirewall->isAllowed().
Problem: Privilege has defined policy
         Tests\Orisai\Auth\Doubles\ArticleEditPolicy.
Solution: Pass policy instead or skip policy and check just privilege with
          UserAwareFirewall->hasPrivilege().
MSG);

		$firewall->isAllowed('article.edit');
	}

	public function testPolicyResourceOwner(): void
	{
		$getter = new UserGetter();
		$authorizer = $this->authorizer();
		$firewall = new UserAwareFirewall($getter, new ArrayLoginStorage(), $this->renewer(), $authorizer);

		$authorizer->addPrivilege('article.edit.all');
		$authorizer->addPrivilege('article.edit.owned');
		$authorizer->addPrivilege('article.view');
		$authorizer->addPrivilege(NeverPassPolicy::getPrivilege());

		$authorizer->addRole('owner');
		$authorizer->addRole('editor');
		$authorizer->addRole('supervisor');

		$authorizer->allow('editor', 'article.edit.all');
		$authorizer->allow('owner', 'article.edit.owned');
		$authorizer->allow('supervisor', Authorizer::ALL_PRIVILEGES);

		$firewall->addPolicy(ArticleEditPolicy::class);
		$firewall->addPolicy(ArticleEditOwnedPolicy::class);
		$firewall->addPolicy(NeverPassPolicy::class);

		$user1 = new User(1);
		$getter->addUser($user1);

		$policy1 = new ArticleEditPolicy(new Article($user1));
		$policy2 = new ArticleEditOwnedPolicy(new Article($user1));

		// Not logged in
		self::assertFalse($firewall->isAllowed($policy1));
		self::assertFalse($firewall->isAllowed($policy2));

		// Logged in, don't have privileges
		$identity1 = new IntIdentity($user1->getId(), []);
		$firewall->login($identity1);

		self::assertFalse($firewall->isAllowed($policy1));
		self::assertFalse($firewall->isAllowed($policy2));

		// Logged in, has access to owned resources
		$identity1 = new IntIdentity($user1->getId(), ['owner']);
		$firewall->login($identity1);

		self::assertTrue($firewall->hasPrivilege('article.edit.owned'));
		self::assertTrue($firewall->isAllowed($policy1));
		self::assertTrue($firewall->isAllowed($policy2));

		// Logged in, does not have access to resource of another user
		$user2 = new User(2);
		$getter->addUser($user2);

		$policy3 = new ArticleEditPolicy(new Article($user2));
		self::assertTrue($firewall->hasPrivilege('article.edit.owned'));
		self::assertFalse($firewall->isAllowed($policy3));

		// Logged in, has access to resources of all users
		$identity1 = new IntIdentity($user1->getId(), ['owner', 'editor']);
		$firewall->login($identity1);

		self::assertTrue($firewall->isAllowed($policy3));

		// - but not other resources
		self::assertFalse($firewall->isAllowed('article.view'));
		self::assertFalse($firewall->isAllowed('article'));
		self::assertFalse($firewall->isAllowed(Authorizer::ALL_PRIVILEGES));

		// Logged in, has access to all resources
		$identity1 = new IntIdentity($user1->getId(), ['supervisor']);
		$firewall->login($identity1);

		self::assertTrue($firewall->isAllowed($policy3));

		self::assertTrue($firewall->isAllowed('article.view'));
		self::assertTrue($firewall->isAllowed('article'));
		self::assertTrue($firewall->isAllowed(Authorizer::ALL_PRIVILEGES));

		// - except these which have defined policy which does not allow it
		self::assertTrue($firewall->hasPrivilege(NeverPassPolicy::getPrivilege()));
		self::assertFalse($firewall->isAllowed(new NeverPassPolicy()));
	}

}
