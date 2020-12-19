<?php declare(strict_types = 1);

namespace Tests\Orisai\Auth\Unit\Authentication\Data;

use Brick\DateTime\Instant;
use Orisai\Auth\Authentication\Data\CurrentLogin;
use Orisai\Auth\Authentication\Data\ExpiredLogin;
use Orisai\Auth\Authentication\Data\Logins;
use Orisai\Auth\Authentication\Firewall;
use Orisai\Auth\Authentication\Identity;
use Orisai\Auth\Authentication\IntIdentity;
use Orisai\Auth\Authentication\StringIdentity;
use PHPUnit\Framework\TestCase;
use function assert;
use function serialize;
use function unserialize;

final class LoginsTest extends TestCase
{

	public function test(): void
	{
		$logins = new Logins();
		self::assertNull($logins->getCurrentLogin());
		self::assertSame([], $logins->getExpiredLogins());

		$currentLogin = new CurrentLogin(new StringIdentity('test', []), Instant::of(1));
		$logins->setCurrentLogin($currentLogin);
		self::assertSame($currentLogin, $logins->getCurrentLogin());

		$logins->removeCurrentLogin();
		self::assertNull($logins->getCurrentLogin());

		$e1 = new ExpiredLogin($currentLogin, Firewall::REASON_MANUAL);
		$logins->addExpiredLogin($e1);
		self::assertSame(['test' => $e1], $logins->getExpiredLogins());

		$logins->setCurrentLogin($currentLogin);
		self::assertSame([], $logins->getExpiredLogins());

		self::assertEquals($logins, unserialize(serialize($logins)));

		// Expired
		$logins->addExpiredLogin($e1);

		$e2 = $this->expiredLogin(new StringIdentity('second', []));
		$logins->addExpiredLogin($e2);

		$e3 = $this->expiredLogin(new IntIdentity(3, []));
		$logins->addExpiredLogin($e3);

		self::assertEquals($logins, unserialize(serialize($logins)));

		self::assertSame(
			[
				'test' => $e1,
				'second' => $e2,
				3 => $e3,
			],
			$logins->getExpiredLogins(),
		);
		$logins->addExpiredLogin($e2);
		self::assertSame(
			[
				'test' => $e1,
				3 => $e3,
				'second' => $e2,
			],
			$logins->getExpiredLogins(),
		);

		// Remove expired by identity id
		$logins->removeExpiredLogin(3);
		self::assertSame(
			[
				'test' => $e1,
				'second' => $e2,
			],
			$logins->getExpiredLogins(),
		);

		// Remove expired by limit
		$logins->addExpiredLogin($e3);
		$logins->removeOldestExpiredLoginsAboveLimit(3);
		self::assertSame(
			[
				'test' => $e1,
				'second' => $e2,
				3 => $e3,
			],
			$logins->getExpiredLogins(),
		);
		$logins->removeOldestExpiredLoginsAboveLimit(2);
		self::assertSame(
			[
				'second' => $e2,
				3 => $e3,
			],
			$logins->getExpiredLogins(),
		);

		// Remove all expired
		$logins->removeExpiredLogins();
		self::assertSame([], $logins->getExpiredLogins());
	}

	private function expiredLogin(Identity $identity): ExpiredLogin
	{
		return new ExpiredLogin(new CurrentLogin($identity, Instant::of(1)), Firewall::REASON_MANUAL);
	}

	public function testIncompleteIdentityClasses(): void
	{
		$serialized = 'O:38:"Orisai\Auth\Authentication\Data\Logins":2:{s:12:"currentLogin";O:44:"Orisai\Auth\Authentication\Data\CurrentLogin":3:{s:8:"identity";O:15:"InvalidIdentity":2:{s:2:"id";s:4:"test";s:5:"roles";a:0:{}}s:18:"authenticationTime";i:1;s:10:"expiration";N;}s:13:"expiredLogins";a:2:{s:6:"second";O:44:"Orisai\Auth\Authentication\Data\ExpiredLogin":4:{s:8:"identity";O:15:"InvalidIdentity":2:{s:2:"id";s:6:"second";s:5:"roles";a:0:{}}s:18:"authenticationTime";i:1;s:12:"logoutReason";i:1;s:10:"expiration";N;}i:3;O:44:"Orisai\Auth\Authentication\Data\ExpiredLogin":4:{s:8:"identity";O:15:"InvalidIdentity":2:{s:2:"id";i:3;s:5:"roles";a:0:{}}s:18:"authenticationTime";i:1;s:12:"logoutReason";i:1;s:10:"expiration";N;}}}';

		$logins = unserialize($serialized);
		assert($logins instanceof Logins);

		self::assertNull($logins->getCurrentLogin());

		self::assertSame(
			[],
			$logins->getExpiredLogins(),
		);
	}

}
