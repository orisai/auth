<?php declare(strict_types = 1);

namespace Tests\Orisai\Auth\Unit\Authorization;

use Orisai\Auth\Authorization\AccessEntryResult;
use PHPUnit\Framework\TestCase;
use ValueError;

final class AccessEntryResultTest extends TestCase
{

	public function test(): void
	{
		self::assertSame('allowed', AccessEntryResult::allowed()->value);
		self::assertSame('Allowed', AccessEntryResult::allowed()->name);
		self::assertSame('forbidden', AccessEntryResult::forbidden()->value);
		self::assertSame('Forbidden', AccessEntryResult::forbidden()->name);
		self::assertSame('skipped', AccessEntryResult::skipped()->value);
		self::assertSame('Skipped', AccessEntryResult::skipped()->name);

		self::assertSame(
			[
				AccessEntryResult::allowed(),
				AccessEntryResult::forbidden(),
				AccessEntryResult::skipped(),
			],
			AccessEntryResult::cases(),
		);

		self::assertSame(AccessEntryResult::allowed(), AccessEntryResult::from('allowed'));
		self::assertSame(AccessEntryResult::allowed(), AccessEntryResult::tryFrom('allowed'));

		self::assertNull(AccessEntryResult::tryFrom('missing'));
		$this->expectException(ValueError::class);
		AccessEntryResult::from('missing');
	}

	public function testFromBool(): void
	{
		self::assertSame(AccessEntryResult::allowed(), AccessEntryResult::fromBool(true));
		self::assertSame(AccessEntryResult::forbidden(), AccessEntryResult::fromBool(false));
	}

}
