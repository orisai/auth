<?php declare(strict_types = 1);

namespace Tests\Orisai\Auth\Unit\Authentication;

use Orisai\Auth\Authentication\LogoutCode;
use PHPUnit\Framework\TestCase;
use ValueError;

final class LogoutCodeTest extends TestCase
{

	public function test(): void
	{
		self::assertSame(1, LogoutCode::manual()->value);
		self::assertSame('manual', LogoutCode::manual()->name);
		self::assertSame(2, LogoutCode::inactivity()->value);
		self::assertSame('inactivity', LogoutCode::inactivity()->name);
		self::assertSame(3, LogoutCode::invalidIdentity()->value);
		self::assertSame('invalidIdentity', LogoutCode::invalidIdentity()->name);

		self::assertEquals(
			[
				LogoutCode::manual(),
				LogoutCode::inactivity(),
				LogoutCode::invalidIdentity(),
			],
			LogoutCode::cases(),
		);

		self::assertEquals(LogoutCode::manual(), LogoutCode::from(1));
		self::assertEquals(LogoutCode::manual(), LogoutCode::tryFrom(1));

		self::assertNull(LogoutCode::tryFrom(4));
		$this->expectException(ValueError::class);
		LogoutCode::from(4);
	}

}
