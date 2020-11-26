<?php declare(strict_types = 1);

namespace Tests\Orisai\Auth\Unit\Authentication\Data;

use Orisai\Auth\Authentication\Data\CurrentExpiration;
use Orisai\Auth\Authentication\Data\CurrentLogin;
use Orisai\Auth\Authentication\Data\Expiration;
use Orisai\Auth\Authentication\Data\ExpiredLogin;
use Orisai\Auth\Authentication\IntIdentity;
use Orisai\Auth\Authentication\LoginStorage;
use PHPUnit\Framework\TestCase;
use function serialize;
use function unserialize;

final class ExpiredLoginTest extends TestCase
{

	public function testBase(): void
	{
		$identity = new IntIdentity(1, []);
		$login = new ExpiredLogin(new CurrentLogin($identity, 2), LoginStorage::REASON_MANUAL);

		self::assertSame($identity, $login->getIdentity());
		self::assertSame(2, $login->getAuthenticationTimestamp());
		self::assertNull($login->getExpiration());
		self::assertSame(LoginStorage::REASON_MANUAL, $login->getLogoutReason());

		self::assertEquals($login, unserialize(serialize($login)));
	}

	public function testExpiration(): void
	{
		$identity = new IntIdentity(1, []);
		$currentLogin = new CurrentLogin($identity, 2);
		$currentLogin->setExpiration(new CurrentExpiration(123, 456));
		$login = new ExpiredLogin($currentLogin, LoginStorage::REASON_MANUAL);

		$expiration = $login->getExpiration();
		self::assertInstanceOf(Expiration::class, $expiration);
		self::assertNotInstanceOf(CurrentLogin::class, $expiration);
		self::assertSame(123, $expiration->getTimestamp());
		self::assertSame(456, $expiration->getDelta());

		self::assertEquals($login, unserialize(serialize($login)));
	}

}
