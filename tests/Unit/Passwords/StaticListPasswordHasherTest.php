<?php declare(strict_types = 1);

namespace Tests\Orisai\Auth\Unit\Passwords;

use PHPUnit\Framework\TestCase;
use Tests\Orisai\Auth\Doubles\StaticListPasswordHasher;

final class StaticListPasswordHasherTest extends TestCase
{

	public function testPasses(): void
	{
		$raw = 'password';

		$hasher = new StaticListPasswordHasher();
		$hashed = $hasher->hash($raw);

		self::assertSame('static_5f4dcc3b5aa765d61d8327deb882cf99', $hashed);
		self::assertFalse($hasher->needsRehash($hashed));
		self::assertTrue($hasher->isValid($raw, $hashed));
	}

	public function testNotPasses(): void
	{
		$hasher = new StaticListPasswordHasher();

		self::assertTrue($hasher->needsRehash('random_string'));
		self::assertFalse($hasher->isValid('random_string', 'static_random_string'));
	}

}
