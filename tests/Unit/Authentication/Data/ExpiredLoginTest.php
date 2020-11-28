<?php declare(strict_types = 1);

namespace Tests\Orisai\Auth\Unit\Authentication\Data;

use Brick\DateTime\Duration;
use Brick\DateTime\Instant;
use Orisai\Auth\Authentication\Data\CurrentExpiration;
use Orisai\Auth\Authentication\Data\CurrentLogin;
use Orisai\Auth\Authentication\Data\Expiration;
use Orisai\Auth\Authentication\Data\ExpiredLogin;
use Orisai\Auth\Authentication\Firewall;
use Orisai\Auth\Authentication\IntIdentity;
use PHPUnit\Framework\TestCase;
use function serialize;
use function unserialize;

final class ExpiredLoginTest extends TestCase
{

	public function testBase(): void
	{
		$identity = new IntIdentity(1, []);
		$authTime = Instant::of(2);
		$login = new ExpiredLogin(new CurrentLogin($identity, $authTime), Firewall::REASON_MANUAL);

		self::assertSame($identity, $login->getIdentity());
		self::assertSame($authTime, $login->getAuthenticationTime());
		self::assertNull($login->getExpiration());
		self::assertSame(Firewall::REASON_MANUAL, $login->getLogoutReason());

		self::assertEquals($login, unserialize(serialize($login)));
	}

	public function testExpiration(): void
	{
		$identity = new IntIdentity(1, []);
		$currentLogin = new CurrentLogin($identity, Instant::of(2));
		$time = Instant::of(123);
		$delta = Duration::ofSeconds(456);
		$currentLogin->setExpiration(new CurrentExpiration($time, $delta));
		$login = new ExpiredLogin($currentLogin, Firewall::REASON_MANUAL);

		$expiration = $login->getExpiration();
		self::assertInstanceOf(Expiration::class, $expiration);
		self::assertNotInstanceOf(CurrentLogin::class, $expiration);
		self::assertSame($time, $expiration->getTime());
		self::assertSame($delta, $expiration->getDelta());

		self::assertEquals($login, unserialize(serialize($login)));
	}

}
