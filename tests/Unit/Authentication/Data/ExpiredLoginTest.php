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
use function assert;
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
		self::assertSame($time, $expiration->getTime());
		self::assertSame($delta, $expiration->getDelta());

		self::assertEquals($login, unserialize(serialize($login)));
	}

	public function testIncompleteIdentityClass(): void
	{
		// phpcs:ignore SlevomatCodingStandard.Files.LineLength.LineTooLong
		$serialized = 'O:44:"Orisai\Auth\Authentication\Data\ExpiredLogin":4:{s:8:"identity";O:15:"InvalidIdentity":2:{s:2:"id";i:1;s:5:"roles";a:0:{}}s:18:"authenticationTime";i:2;s:12:"logoutReason";i:1;s:10:"expiration";O:42:"Orisai\Auth\Authentication\Data\Expiration":2:{s:4:"time";i:123;s:5:"delta";i:456;}}';

		$login = unserialize($serialized);
		assert($login instanceof ExpiredLogin);

		self::assertTrue($login->hasInvalidIdentity());
	}

}
