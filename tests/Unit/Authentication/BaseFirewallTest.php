<?php declare(strict_types = 1);

namespace Tests\Orisai\Auth\Unit\Authentication;

use Brick\DateTime\Clock\FixedClock;
use Brick\DateTime\Instant;
use Generator;
use Orisai\Auth\Authentication\ArrayLoginStorage;
use Orisai\Auth\Authentication\Exception\NotLoggedIn;
use Orisai\Auth\Authentication\IntIdentity;
use Orisai\Auth\Authentication\StringIdentity;
use Orisai\Auth\Authorization\AuthorizationDataBuilder;
use Orisai\Auth\Authorization\PolicyManager;
use Orisai\Auth\Authorization\PrivilegeAuthorizer;
use Orisai\Auth\Authorization\SimplePolicyManager;
use Orisai\Exceptions\Logic\InvalidArgument;
use PHPUnit\Framework\TestCase;
use Tests\Orisai\Auth\Doubles\AlwaysPassIdentityRenewer;
use Tests\Orisai\Auth\Doubles\NeverPassIdentityRenewer;
use Tests\Orisai\Auth\Doubles\NewIdentityIdentityRenewer;
use Tests\Orisai\Auth\Doubles\TestingArrayLoginStorage;
use Tests\Orisai\Auth\Doubles\TestingFirewall;
use Throwable;
use function array_keys;

final class BaseFirewallTest extends TestCase
{

	private function renewer(): AlwaysPassIdentityRenewer
	{
		return new AlwaysPassIdentityRenewer();
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
		self::assertNull($expired->getLogoutReasonDescription());

		$this->expectException(NotLoggedIn::class);
		$firewall->getIdentity();
	}

	public function testSeparateNamespaces(): void
	{
		$storage = new ArrayLoginStorage();
		$identity = new IntIdentity(123, []);

		$firewall1 = new TestingFirewall(
			$storage,
			$this->renewer(),
			$this->authorizer(),
			null,
			'one',
		);
		$firewall2 = new TestingFirewall(
			$storage,
			$this->renewer(),
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

	/**
	 * @dataProvider provideRenewerRemovedIdentity
	 */
	public function testRenewerRemovedIdentity(?string $reasonDescription): void
	{
		$identity = new IntIdentity(123, []);

		$storage = new ArrayLoginStorage();
		$renewer = new NeverPassIdentityRenewer($reasonDescription);
		$firewall = new TestingFirewall($storage, $renewer, $this->authorizer());

		$firewall->login($identity);
		self::assertSame($identity, $firewall->getIdentity());
		self::assertSame([], $firewall->getExpiredLogins());

		$firewall->resetLoginsChecks();

		$expired = $firewall->getExpiredLogins()[123];
		self::assertSame($identity, $expired->getIdentity());
		self::assertSame($firewall::REASON_INVALID_IDENTITY, $expired->getLogoutReason());
		self::assertSame($reasonDescription, $expired->getLogoutReasonDescription());
	}

	/**
	 * @return Generator<array<mixed>>
	 */
	public function provideRenewerRemovedIdentity(): Generator
	{
		yield [null];
		yield ['reason description'];
	}

	public function testSecurityTokenRegenerates(): void
	{
		$storage = new TestingArrayLoginStorage();
		$renewer = new NeverPassIdentityRenewer();
		$firewall = new TestingFirewall(
			$storage,
			$renewer,
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
		self::assertNull($expired->getLogoutReasonDescription());

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

	public function testExpirationTimeIsRightNow(): void
	{
		$storage = new ArrayLoginStorage();
		$clock = new FixedClock(Instant::of(1));
		$firewall = new TestingFirewall(
			$storage,
			$this->renewer(),
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

		$firewall->setExpiration($clock->getTime());
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

	public function testGetExpirationTime(): void
	{
		$storage = new ArrayLoginStorage();
		$clock = new FixedClock(Instant::of(1));
		$firewall = new TestingFirewall(
			$storage,
			$this->renewer(),
			$this->authorizer(),
			$clock,
		);

		$identity = new IntIdentity(123, []);

		$firewall->login($identity);
		self::assertNull($firewall->getExpirationTime());

		$expiration = Instant::of(5);
		$firewall->setExpiration($expiration);
		self::assertSame(5, $firewall->getExpirationTime()->getEpochSecond());

		$firewall->resetLoginsChecks();
		$clock->move(1);
		self::assertSame(6, $firewall->getExpirationTime()->getEpochSecond());
	}

	public function testNotLoggedInGetExpirationTime(): void
	{
		$storage = new ArrayLoginStorage();
		$firewall = new TestingFirewall($storage, $this->renewer(), $this->authorizer());

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
		$firewall = new TestingFirewall(
			$storage,
			$this->renewer(),
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
		$builder = new AuthorizationDataBuilder();

		$builder->addPrivilege('admin');
		$builder->addPrivilege('front');

		$builder->addRole('guest');

		$builder->allow('guest', 'front');

		$storage = new ArrayLoginStorage();
		$authorizer = $this->authorizer(null, $builder);
		$firewall = new TestingFirewall($storage, $this->renewer(), $authorizer, null, 'test');

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

	public function testRemovalMethodsSoftFail(): void
	{
		$storage = new ArrayLoginStorage();
		$namespace = 'test';
		$firewall = new TestingFirewall(
			$storage,
			$this->renewer(),
			$this->authorizer(),
			null,
			$namespace,
		);

		$exception = null;
		try {
			$firewall->logout();
			$firewall->removeExpiration();
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

}
