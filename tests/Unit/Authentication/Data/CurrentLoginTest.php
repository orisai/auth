<?php declare(strict_types = 1);

namespace Tests\Orisai\Auth\Unit\Authentication\Data;

use Brick\DateTime\Duration;
use Brick\DateTime\Instant;
use Orisai\Auth\Authentication\Data\CurrentExpiration;
use Orisai\Auth\Authentication\Data\CurrentLogin;
use Orisai\Auth\Authentication\IntIdentity;
use Orisai\Auth\Authentication\StringIdentity;
use PHPUnit\Framework\TestCase;
use function serialize;
use function unserialize;

final class CurrentLoginTest extends TestCase
{

	public function test(): void
	{
		$identity = new IntIdentity(1, []);
		$authTime = Instant::of(2);
		$login = new CurrentLogin($identity, $authTime);

		self::assertSame($identity, $login->getIdentity());
		self::assertSame($authTime, $login->getAuthenticationTime());
		self::assertNull($login->getExpiration());

		$expiration = new CurrentExpiration(Instant::of(123), Duration::ofSeconds(456));
		$login->setExpiration($expiration);
		self::assertSame($expiration, $login->getExpiration());

		$identity = new StringIdentity('test', []);
		$login->setIdentity($identity);
		self::assertSame($identity, $login->getIdentity());

		self::assertEquals($login, unserialize(serialize($login)));
	}

}
