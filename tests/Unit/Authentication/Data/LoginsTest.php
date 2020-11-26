<?php declare(strict_types = 1);

namespace Tests\Orisai\Auth\Unit\Authentication\Data;

use Orisai\Auth\Authentication\Data\CurrentLogin;
use Orisai\Auth\Authentication\Data\ExpiredLogin;
use Orisai\Auth\Authentication\Data\Logins;
use Orisai\Auth\Authentication\Identity;
use Orisai\Auth\Authentication\IntIdentity;
use Orisai\Auth\Authentication\LoginStorage;
use Orisai\Auth\Authentication\StringIdentity;
use PHPUnit\Framework\TestCase;
use function serialize;
use function unserialize;

final class LoginsTest extends TestCase
{

	public function test(): void
	{
		$logins = new Logins();
		self::assertNull($logins->getCurrentLogin());
		self::assertSame([], $logins->getExpiredLogins());

		$currentLogin = new CurrentLogin(new StringIdentity('test', []), 1);
		$logins->setCurrentLogin($currentLogin);
		self::assertSame($currentLogin, $logins->getCurrentLogin());

		$logins->removeCurrentLogin();
		self::assertNull($logins->getCurrentLogin());

		$e1 = new ExpiredLogin($currentLogin, LoginStorage::REASON_MANUAL);
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
		return new ExpiredLogin(new CurrentLogin($identity, 1), LoginStorage::REASON_MANUAL);
	}

}