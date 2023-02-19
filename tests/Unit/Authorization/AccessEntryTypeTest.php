<?php declare(strict_types = 1);

namespace Tests\Orisai\Auth\Unit\Authorization;

use Orisai\Auth\Authorization\AccessEntryType;
use PHPUnit\Framework\TestCase;
use ValueError;

final class AccessEntryTypeTest extends TestCase
{

	public function test(): void
	{
		self::assertSame('allowed', AccessEntryType::allowed()->value);
		self::assertSame('Allowed', AccessEntryType::allowed()->name);
		self::assertSame('forbidden', AccessEntryType::forbidden()->value);
		self::assertSame('Forbidden', AccessEntryType::forbidden()->name);
		self::assertSame('skipped', AccessEntryType::skipped()->value);
		self::assertSame('Skipped', AccessEntryType::skipped()->name);

		self::assertSame(
			[
				AccessEntryType::allowed(),
				AccessEntryType::forbidden(),
				AccessEntryType::skipped(),
			],
			AccessEntryType::cases(),
		);

		self::assertSame(AccessEntryType::allowed(), AccessEntryType::from('allowed'));
		self::assertSame(AccessEntryType::allowed(), AccessEntryType::tryFrom('allowed'));

		self::assertNull(AccessEntryType::tryFrom('missing'));
		$this->expectException(ValueError::class);
		AccessEntryType::from('missing');
	}

	public function testFromBool(): void
	{
		self::assertSame(AccessEntryType::allowed(), AccessEntryType::fromBool(true));
		self::assertSame(AccessEntryType::forbidden(), AccessEntryType::fromBool(false));
	}

}
