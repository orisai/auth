<?php declare(strict_types = 1);

namespace Tests\Orisai\Auth\Unit\Passwords;

use Generator;
use Orisai\Auth\Passwords\UnsafeMD5PasswordEncoder;
use PHPUnit\Framework\TestCase;

final class UnsafeMD5PasswordEncoderTest extends TestCase
{

	public function testPasses(): void
	{
		$raw = 'password';

		$encoder = new UnsafeMD5PasswordEncoder();
		$encoded = $encoder->encode($raw);

		self::assertFalse($encoder->needsReEncode($encoded));
		self::assertTrue($encoder->isValid($raw, $encoded));
	}

	/**
	 * @dataProvider providePreGeneratedPasses
	 */
	public function testPreGeneratedPasses(string $raw, string $encoded): void
	{
		$encoder = new UnsafeMD5PasswordEncoder();
		self::assertFalse($encoder->needsReEncode($encoded));
		self::assertTrue($encoder->isValid($raw, $encoded));
	}

	/**
	 * @return Generator<array<mixed>>
	 */
	public function providePreGeneratedPasses(): Generator
	{
		yield ['password', '$1$5f4dcc3b5aa765d61d8327deb882cf99'];
		yield ['1234', '$1$81dc9bdb52d04dc20036dbd8313ed055'];
	}

	/**
	 * @dataProvider providePreGeneratedNotPasses
	 */
	public function testPreGeneratedNotPasses(string $raw, string $encoded, bool $needsReEncode): void
	{
		$encoder = new UnsafeMD5PasswordEncoder();
		self::assertSame($needsReEncode, $encoder->needsReEncode($encoded));
		self::assertFalse($encoder->isValid($raw, $encoded));
	}

	/**
	 * @return Generator<array<mixed>>
	 */
	public function providePreGeneratedNotPasses(): Generator
	{
		// Invalid hash
		yield ['password', '$1$5f4dcc3b5aadddd61d8327deb882cf99', false];
		yield ['1234', '$1$5f4dcc3b5aa765d61d8327deb882cf99', false];

		// Different algorithm
		yield ['password', '$5y$09$tD9kmDjFoiws/6ioiR.25uwPuC0Cn9MWPKUn9Uugb5IqA.3HpN8Hq', true];
		yield ['password', '$2y$10$WfjR3j4GPLEYUNPJ/MRw0.UQ3Ar12XSY4XH65XCNUXg04i9tniR6m', true];
		yield ['1234', 'loremipsum', true];
	}

}
