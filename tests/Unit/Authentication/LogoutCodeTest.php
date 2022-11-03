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
		self::assertSame('Manual', LogoutCode::manual()->name);
		self::assertSame(2, LogoutCode::inactivity()->value);
		self::assertSame('Inactivity', LogoutCode::inactivity()->name);
		self::assertSame(3, LogoutCode::invalidIdentity()->value);
		self::assertSame('InvalidIdentity', LogoutCode::invalidIdentity()->name);

		self::assertSame(
			[
				LogoutCode::manual(),
				LogoutCode::inactivity(),
				LogoutCode::invalidIdentity(),
			],
			LogoutCode::cases(),
		);

		self::assertSame(LogoutCode::manual(), LogoutCode::from(1));
		self::assertSame(LogoutCode::manual(), LogoutCode::tryFrom(1));

		self::assertNull(LogoutCode::tryFrom(4));
		$this->expectException(ValueError::class);
		LogoutCode::from(4);
	}

}
