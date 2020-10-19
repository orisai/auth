<?php declare(strict_types = 1);

namespace Tests\Orisai\Auth\Unit\Passwords;

use PHPUnit\Framework\TestCase;
use Tests\Orisai\Auth\Doubles\StaticListPasswordEncoder;

final class StaticListPasswordEncoderTest extends TestCase
{

	public function testPasses(): void
	{
		$raw = 'password';

		$encoder = new StaticListPasswordEncoder();
		$encoded = $encoder->encode($raw);

		self::assertSame('static_5f4dcc3b5aa765d61d8327deb882cf99', $encoded);
		self::assertFalse($encoder->needsReEncode($encoded));
		self::assertTrue($encoder->isValid($raw, $encoded));

	}

	public function testNotPasses(): void
	{
		$encoder = new StaticListPasswordEncoder();

		self::assertTrue($encoder->needsReEncode('random_string'));
		self::assertFalse($encoder->isValid('random_string', 'static_random_string'));
	}

}
