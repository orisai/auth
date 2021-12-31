<?php declare(strict_types = 1);

namespace Tests\Orisai\Auth\Unit\Authentication;

use Brick\DateTime\Clock\FixedClock;
use Brick\DateTime\Instant;
use Generator;
use Orisai\Auth\Authentication\ArrayLoginStorage;
use Orisai\Auth\Authentication\DecisionReason;
use Orisai\Auth\Authentication\Exception\NotLoggedIn;
use Orisai\Auth\Authentication\IntIdentity;
use Orisai\Auth\Authentication\StringIdentity;
use Orisai\Auth\Authorization\AuthorizationDataBuilder;
use Orisai\Auth\Authorization\PolicyManager;
use Orisai\Auth\Authorization\PrivilegeAuthorizer;
use Orisai\Auth\Authorization\SimplePolicyManager;
use Orisai\Exceptions\Logic\InvalidArgument;
use PHPUnit\Framework\TestCase;
use Tests\Orisai\Auth\Doubles\AddDecisionReasonPolicy;
use Tests\Orisai\Auth\Doubles\AlwaysPassIdentityRefresher;
use Tests\Orisai\Auth\Doubles\NeverPassIdentityRefresher;
use Tests\Orisai\Auth\Doubles\NewIdentityIdentityRefresher;
use Tests\Orisai\Auth\Doubles\NoRequirementsPolicy;
use Tests\Orisai\Auth\Doubles\PassWithNoIdentityPolicy;
use Tests\Orisai\Auth\Doubles\RequireCurrentUserPolicy;
use Tests\Orisai\Auth\Doubles\TestingArrayLoginStorage;
use Tests\Orisai\Auth\Doubles\TestingFirewall;
use Tests\Orisai\Auth\Doubles\User;
use Tests\Orisai\Auth\Doubles\UserAwareFirewall;
use Tests\Orisai\Auth\Doubles\UserGetter;
use Throwable;
use function array_keys;

final class BaseFirewallTest extends TestCase
{

	private function refresher(): AlwaysPassIdentityRefresher
	{
		return new AlwaysPassIdentityRefresher();
	}

	private function authorizer(
		?PolicyManager $policyManager = null,
		?AuthorizationDataBuilder $builder = null
	): PrivilegeAuthorizer
	{
		$builder ??= new AuthorizationDataBuilder();

		return new PrivilegeAuthorizer(
			$policyManager ?? $this->policies(),
			$builder->build(),
		);
	}

	private function policies(): SimplePolicyManager
	{
		return new SimplePolicyManager();
	}

	public function testBase(): void
	{
		$storage = new ArrayLoginStorage();
		$firewall = new TestingFirewall($storage, $this->refresher(), $this->authorizer());
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
		self::assertSame($firewall::REASON_MANUAL, $expired->getLogoutCode());
		self::assertNull($expired->getLogoutReason());

		$this->expectException(NotLoggedIn::class);
		$firewall->getIdentity();
	}

	public function testSeparateNamespaces(): void
	{
		$storage = new ArrayLoginStorage();
		$identity = new IntIdentity(123, []);

		$firewall1 = new TestingFirewall(
			$storage,
			$this->refresher(),
			$this->authorizer(),
			null,
			'one',
		);
		$firewall2 = new TestingFirewall(
			$storage,
			$this->refresher(),
			$this->authorizer(),
			null,
			'two',
		);

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

	public function testPolicyDecisionReason(): void
	{
		$policyManager = $this->policies();
		$policyManager->add(new NoRequirementsPolicy());
		$policyManager->add(new AddDecisionReasonPolicy());

		$builder = new AuthorizationDataBuilder();
		$builder->addPrivilege(NoRequirementsPolicy::getPrivilege());
		$builder->addPrivilege(AddDecisionReasonPolicy::getPrivilege());

		$authorizer = $this->authorizer($policyManager, $builder);

		$firewall = new TestingFirewall(new ArrayLoginStorage(), $this->refresher(), $authorizer);

		$firewall->login(new IntIdentity(1, []));

		$firewall->isAllowed(NoRequirementsPolicy::getPrivilege(), null, $reason);
		self::assertNull($reason);

		$firewall->isAllowed(AddDecisionReasonPolicy::getPrivilege(), null, $reason);
		self::assertInstanceOf(DecisionReason::class, $reason);
	}

	public function testIdentityClassUpdate(): void
	{
		$originalIdentity = new IntIdentity(123, []);
		$refreshedIdentity = new StringIdentity('string', []);

		$storage = new ArrayLoginStorage();
		$firewall = new TestingFirewall(
			$storage,
			new NewIdentityIdentityRefresher($refreshedIdentity),
			$this->authorizer(),
		);

		$firewall->login($originalIdentity);
		$firewall->resetLoginsChecks();
		self::assertSame($refreshedIdentity, $firewall->getLogins()->getCurrentLogin()->getIdentity());
	}

	public function testHasRole(): void
	{
		$identity = new IntIdentity(123, ['foo']);

		$storage = new ArrayLoginStorage();
		$firewall = new TestingFirewall($storage, $this->refresher(), $this->authorizer());

		self::assertFalse($firewall->hasRole('foo'));

		$firewall->login($identity);
		self::assertTrue($firewall->hasRole('foo'));
		self::assertFalse($firewall->hasRole('bar'));
	}

	public function testExpiredIdentities(): void
	{
		$storage = new ArrayLoginStorage();
		$firewall = new TestingFirewall($storage, $this->refresher(), $this->authorizer());
		$firewall->setExpiredIdentitiesLimit(3);
		$identity1 = new IntIdentity(1, []);

		$firewall->login($identity1);
		self::assertSame([], $firewall->getExpiredLogins());

		$firewall->logout();
		self::assertSame([1], array_keys($firewall->getExpiredLogins()));
		self::assertSame($identity1, $firewall->getLastExpiredLogin()->getIdentity());

		$firewall->login($identity1);
		self::assertSame([], $firewall->getExpiredLogins());
		self::assertNull($firewall->getLastExpiredLogin());

		$identity2 = new StringIdentity('second', []);
		$firewall->login($identity2);
		self::assertSame([1], array_keys($firewall->getExpiredLogins()));

		$firewall->logout();
		self::assertSame([1, 'second'], array_keys($firewall->getExpiredLogins()));
		self::assertSame($identity2, $firewall->getLastExpiredLogin()->getIdentity());

		$identity3 = new IntIdentity(3, []);
		$firewall->login($identity3);
		$firewall->login($identity2);
		$firewall->logout();
		self::assertSame([1, 3, 'second'], array_keys($firewall->getExpiredLogins()));
		self::assertSame($identity2, $firewall->getLastExpiredLogin()->getIdentity());

		// logout removes logins above limit
		$identity4 = new IntIdentity(4, []);
		$firewall->login($identity4);
		$firewall->logout();
		self::assertSame([3, 'second', 4], array_keys($firewall->getExpiredLogins()));
		self::assertSame($identity4, $firewall->getLastExpiredLogin()->getIdentity());

		// new login also removes logins above limit
		$firewall->login($identity1);
		$identity5 = new StringIdentity('fifth', []);
		$firewall->login($identity5);
		self::assertSame(['second', 4, 1], array_keys($firewall->getExpiredLogins()));
		self::assertSame($identity1, $firewall->getLastExpiredLogin()->getIdentity());

		// Remove expired login with specific ID
		$firewall->removeExpiredLogin(4);
		self::assertSame(['second', 1], array_keys($firewall->getExpiredLogins()));
		self::assertSame($identity1, $firewall->getLastExpiredLogin()->getIdentity());

		// Remove expired logins above limit
		$firewall->setExpiredIdentitiesLimit(1);
		self::assertSame([1], array_keys($firewall->getExpiredLogins()));
		self::assertSame($identity1, $firewall->getLastExpiredLogin()->getIdentity());

		// Remove all expired logins
		$firewall->removeExpiredLogins();
		self::assertSame([], $firewall->getExpiredLogins());
		self::assertNull($firewall->getLastExpiredLogin());
	}

	public function testManualRefreshIdentity(): void
	{
		$storage = new ArrayLoginStorage();
		$firewall = new TestingFirewall($storage, $this->refresher(), $this->authorizer());
		$identity = new IntIdentity(123, []);

		$firewall->login($identity);
		self::assertSame($identity, $firewall->getIdentity());

		$firewall->refreshIdentity($identity);
		self::assertSame($identity, $firewall->getIdentity());

		$newIdentity = new IntIdentity(456, []);
		$firewall->refreshIdentity($newIdentity);
		self::assertSame($newIdentity, $firewall->getIdentity());
	}

	public function testManualRefreshIdentityFailure(): void
	{
		$storage = new ArrayLoginStorage();
		$firewall = new TestingFirewall($storage, $this->refresher(), $this->authorizer());
		$identity = new IntIdentity(123, []);

		$this->expectException(NotLoggedIn::class);
		$this->expectExceptionMessage(<<<'MSG'
Context: Calling Tests\Orisai\Auth\Doubles\TestingFirewall->refreshIdentity().
Problem: User is not logged in firewall.
Solution: Login with TestingFirewall->login($identity) or check with
          TestingFirewall->isLoggedIn().
MSG);

		$firewall->refreshIdentity($identity);
	}

	public function testRefreshSameIdentity(): void
	{
		$identity = new IntIdentity(123, []);

		$storage = new ArrayLoginStorage();
		$refresher = new AlwaysPassIdentityRefresher();
		$firewall = new TestingFirewall($storage, $refresher, $this->authorizer());

		$firewall->login($identity);
		self::assertSame($identity, $firewall->getIdentity());
		self::assertSame([], $firewall->getExpiredLogins());

		$firewall->resetLoginsChecks();

		self::assertSame($identity, $firewall->getIdentity());
		self::assertSame([], $firewall->getExpiredLogins());
	}

	public function testRefresherNewIdentity(): void
	{
		$originalIdentity = new IntIdentity(123, []);
		$newIdentity = new IntIdentity(456, []);

		$storage = new ArrayLoginStorage();
		$refresher = new NewIdentityIdentityRefresher($newIdentity);
		$firewall = new TestingFirewall($storage, $refresher, $this->authorizer());

		$firewall->login($originalIdentity);
		self::assertSame($originalIdentity, $firewall->getIdentity());
		self::assertSame([], $firewall->getExpiredLogins());

		$firewall->resetLoginsChecks();

		self::assertSame($newIdentity, $firewall->getIdentity());
		self::assertSame([], $firewall->getExpiredLogins());
	}

	/**
	 * @dataProvider provideRefresherRemovedIdentity
	 */
	public function testRefresherRemovedIdentity(?DecisionReason $reasonDescription): void
	{
		$identity = new IntIdentity(123, []);

		$storage = new ArrayLoginStorage();
		$refresher = new NeverPassIdentityRefresher($reasonDescription);
		$firewall = new TestingFirewall($storage, $refresher, $this->authorizer());

		$firewall->login($identity);
		self::assertSame($identity, $firewall->getIdentity());
		self::assertSame([], $firewall->getExpiredLogins());

		$firewall->resetLoginsChecks();

		$expired = $firewall->getExpiredLogins()[123];
		self::assertSame($identity, $expired->getIdentity());
		self::assertSame($firewall::REASON_INVALID_IDENTITY, $expired->getLogoutCode());
		self::assertSame($reasonDescription, $expired->getLogoutReason());
	}

	/**
	 * @return Generator<array<mixed>>
	 */
	public function provideRefresherRemovedIdentity(): Generator
	{
		yield [null];
		yield [DecisionReason::create('reason description')];
	}

	public function testSecurityTokenRegenerates(): void
	{
		$storage = new TestingArrayLoginStorage();
		$refresher = new NeverPassIdentityRefresher();
		$firewall = new TestingFirewall(
			$storage,
			$refresher,
			$this->authorizer(),
		);
		$namespace = $firewall->getNamespace();
		$identity = new IntIdentity(123, []);

		$token1 = $storage->getToken($namespace);
		$token2 = $storage->getToken($namespace);
		self::assertSame($token1, $token2);

		$firewall->login($identity);
		$token3 = $storage->getToken($namespace);
		self::assertNotSame($token2, $token3);

		$firewall->login($identity);
		$token4 = $storage->getToken($namespace);
		self::assertNotSame($token3, $token4);

		$firewall->logout();
		$token5 = $storage->getToken($namespace);
		self::assertNotSame($token4, $token5);

		$firewall->login($identity);
		$token6 = $storage->getToken($namespace);

		$firewall->resetLoginsChecks();
		self::assertFalse($firewall->isLoggedIn());

		$token7 = $storage->getToken($namespace);
		self::assertNotSame($token6, $token7);
	}

	public function testTimeExpiredIdentity(): void
	{
		$clock = new FixedClock(Instant::now());
		$storage = new ArrayLoginStorage();
		$firewall = new TestingFirewall($storage, $this->refresher(), $this->authorizer(), $clock);
		$identity = new IntIdentity(123, []);

		$firewall->login($identity);
		$firewall->setExpirationTime(Instant::now()->plusSeconds(1));
		self::assertSame($identity, $firewall->getIdentity());

		$clock->move(2);
		$firewall->resetLoginsChecks();

		self::assertFalse($firewall->isLoggedIn());
		$expired = $firewall->getExpiredLogins()[123];
		self::assertSame($identity, $expired->getIdentity());
		self::assertSame($firewall::REASON_INACTIVITY, $expired->getLogoutCode());
		self::assertNull($expired->getLogoutReason());

		$firewall->login($identity);
		self::assertTrue($firewall->isLoggedIn());
		self::assertSame($identity, $firewall->getIdentity());
		self::assertSame([], $firewall->getExpiredLogins());
	}

	public function testNotTimeExpiredIdentity(): void
	{
		$storage = new ArrayLoginStorage();
		$firewall = new TestingFirewall($storage, $this->refresher(), $this->authorizer());
		$identity = new IntIdentity(123, []);

		$firewall->login($identity);
		$firewall->setExpirationTime(Instant::now()->plusMinutes(10));
		self::assertSame($identity, $firewall->getIdentity());

		$firewall->resetLoginsChecks();

		self::assertSame($identity, $firewall->getIdentity());
		self::assertSame([], $firewall->getExpiredLogins());
	}

	public function testRemovedTimeExpiration(): void
	{
		$clock = new FixedClock(Instant::now());
		$storage = new ArrayLoginStorage();
		$firewall = new TestingFirewall($storage, $this->refresher(), $this->authorizer(), $clock);
		$identity = new IntIdentity(123, []);

		$firewall->login($identity);
		$firewall->setExpirationTime(Instant::now()->plusSeconds(1));
		$firewall->removeExpirationTime();
		self::assertSame($identity, $firewall->getIdentity());

		$clock->move(2);
		$firewall->resetLoginsChecks();

		self::assertSame($identity, $firewall->getIdentity());
		self::assertSame([], $firewall->getExpiredLogins());
	}

	public function testExpirationTimeInThePast(): void
	{
		$storage = new ArrayLoginStorage();
		$firewall = new TestingFirewall($storage, $this->refresher(), $this->authorizer());
		$identity = new IntIdentity(123, []);

		$firewall->login($identity);

		$this->expectException(InvalidArgument::class);
		$this->expectExceptionMessage(<<<'MSG'
Context: Trying to set login expiration time.
Problem: Expiration time is lower than current time.
Solution: Choose expiration time which is in future.
MSG);

		$firewall->setExpirationTime(Instant::now()->minusSeconds(10));
	}

	public function testExpirationTimeIsRightNow(): void
	{
		$storage = new ArrayLoginStorage();
		$clock = new FixedClock(Instant::of(1));
		$firewall = new TestingFirewall(
			$storage,
			$this->refresher(),
			$this->authorizer(),
			$clock,
		);
		$identity = new IntIdentity(123, []);

		$firewall->login($identity);

		$this->expectException(InvalidArgument::class);
		$this->expectExceptionMessage(<<<'MSG'
Context: Trying to set login expiration time.
Problem: Expiration time is lower than current time.
Solution: Choose expiration time which is in future.
MSG);

		$firewall->setExpirationTime($clock->getTime());
	}

	public function testExpirationCannotBeSet(): void
	{
		$storage = new ArrayLoginStorage();
		$firewall = new TestingFirewall($storage, $this->refresher(), $this->authorizer());

		$this->expectException(NotLoggedIn::class);
		$this->expectExceptionMessage(<<<'MSG'
Context: Calling Tests\Orisai\Auth\Doubles\TestingFirewall->setExpirationTime().
Problem: User is not logged in firewall.
Solution: Login with TestingFirewall->login($identity) or check with
          TestingFirewall->isLoggedIn().
MSG);

		$firewall->setExpirationTime(Instant::now()->minusSeconds(10));
	}

	public function testGetExpirationTime(): void
	{
		$storage = new ArrayLoginStorage();
		$clock = new FixedClock(Instant::of(1));
		$firewall = new TestingFirewall(
			$storage,
			$this->refresher(),
			$this->authorizer(),
			$clock,
		);

		$identity = new IntIdentity(123, []);

		$firewall->login($identity);
		self::assertNull($firewall->getExpirationTime());

		$expiration = Instant::of(5);
		$firewall->setExpirationTime($expiration);
		self::assertSame(5, $firewall->getExpirationTime()->getEpochSecond());

		$firewall->resetLoginsChecks();
		$clock->move(1);
		self::assertSame(6, $firewall->getExpirationTime()->getEpochSecond());
	}

	public function testNotLoggedInGetExpirationTime(): void
	{
		$storage = new ArrayLoginStorage();
		$firewall = new TestingFirewall($storage, $this->refresher(), $this->authorizer());

		$this->expectException(NotLoggedIn::class);
		$this->expectExceptionMessage(<<<'MSG'
Context: Calling Tests\Orisai\Auth\Doubles\TestingFirewall->getExpirationTime().
Problem: User is not logged in firewall.
Solution: Login with TestingFirewall->login($identity) or check with
          TestingFirewall->isLoggedIn().
MSG);

		$firewall->getExpirationTime();
	}

	public function testNotLoggedInGetIdentity(): void
	{
		$storage = new ArrayLoginStorage();
		$firewall = new TestingFirewall($storage, $this->refresher(), $this->authorizer());

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
			$this->refresher(),
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
		$firewall = new TestingFirewall($storage, $this->refresher(), $this->authorizer());

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
		$firewall = new TestingFirewall(
			$storage,
			$this->refresher(),
			$this->authorizer(),
			null,
			$namespace,
		);

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

		self::assertNull($firewall->getLastExpiredLogin());
		self::assertFalse($storage->alreadyExists($namespace));

		self::assertFalse($firewall->hasRole('any'));
		self::assertFalse($storage->alreadyExists($namespace));

		self::assertFalse($firewall->isAllowed('any'));
		self::assertFalse($storage->alreadyExists($namespace));

		$firewall->logout();
		self::assertFalse($storage->alreadyExists($namespace));

		$firewall->removeExpirationTime();
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
		$builder = new AuthorizationDataBuilder();

		$builder->addPrivilege('admin');
		$builder->addPrivilege('front');

		$builder->addRole('guest');

		$builder->allow('guest', 'front');

		$storage = new ArrayLoginStorage();
		$authorizer = $this->authorizer(null, $builder);
		$firewall = new TestingFirewall($storage, $this->refresher(), $authorizer, null, 'test');

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

	public function testPolicy(): void
	{
		$policyManager = $this->policies();
		$policyManager->add(new PassWithNoIdentityPolicy());
		$policyManager->add(new NoRequirementsPolicy());

		$builder = new AuthorizationDataBuilder();
		$builder->addPrivilege(PassWithNoIdentityPolicy::getPrivilege());
		$builder->addPrivilege(NoRequirementsPolicy::getPrivilege());

		$storage = new ArrayLoginStorage();
		$authorizer = $this->authorizer($policyManager, $builder);
		$firewall = new TestingFirewall($storage, $this->refresher(), $authorizer, null, 'test');

		self::assertTrue(
			$firewall->isAllowed(PassWithNoIdentityPolicy::getPrivilege()),
		);
		self::assertFalse(
			$firewall->isAllowed(NoRequirementsPolicy::getPrivilege()),
		);

		$firewall->login(new IntIdentity(1, []));
		self::assertFalse(
			$firewall->isAllowed(PassWithNoIdentityPolicy::getPrivilege()),
		);
		self::assertTrue(
			$firewall->isAllowed(NoRequirementsPolicy::getPrivilege()),
		);
	}

	public function testRemovalMethodsSoftFail(): void
	{
		$storage = new ArrayLoginStorage();
		$namespace = 'test';
		$firewall = new TestingFirewall(
			$storage,
			$this->refresher(),
			$this->authorizer(),
			null,
			$namespace,
		);

		$exception = null;
		try {
			$firewall->logout();
			$firewall->removeExpirationTime();
			$firewall->removeExpiredLogin(123);
			$firewall->removeExpiredLogins();
		} catch (Throwable $exception) {
			// Handled below
		}

		self::assertNull($exception);

		// Tests a case in which unauthenticate() is called with existing logins and no current login

		self::assertFalse($storage->alreadyExists($namespace));
		$storage->getLogins($namespace); // Triggers storage creation
		self::assertTrue($storage->alreadyExists($namespace));

		$exception = null;
		try {
			$firewall->logout();
		} catch (Throwable $exception) {
			// Handled below
		}

		self::assertNull($exception);
	}

	public function testUserAwareFirewall(): void
	{
		$storage = new ArrayLoginStorage();
		$getter = new UserGetter();
		$firewall = new UserAwareFirewall(
			$getter,
			$storage,
			$this->refresher(),
			$this->authorizer(),
		);

		$identity = new IntIdentity(123, []);
		$user = new User(123);
		$getter->addUser($user);

		$firewall->login($identity);
		$firewallUser = $firewall->getUser();
		self::assertSame($user, $firewallUser);
	}

	public function testCurrentUserPolicy(): void
	{
		$storage = new ArrayLoginStorage();

		$builder = new AuthorizationDataBuilder();
		$builder->addPrivilege(RequireCurrentUserPolicy::getPrivilege());

		$policyManager = new SimplePolicyManager();
		$policyManager->add(new RequireCurrentUserPolicy());

		$firewall = new TestingFirewall(
			$storage,
			$this->refresher(),
			$this->authorizer($policyManager, $builder),
		);
		$identity = new IntIdentity(123, []);

		$firewall->login($identity);
		self::assertTrue($firewall->isAllowed(RequireCurrentUserPolicy::getPrivilege()));
	}

}
