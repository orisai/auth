<?php declare(strict_types = 1);

namespace Tests\Orisai\Auth\Unit\Passwords;

use Generator;
use Orisai\Auth\Passwords\BcryptPasswordEncoder;
use Orisai\Exceptions\Logic\InvalidArgument;
use PHPUnit\Framework\TestCase;

final class BcryptPasswordEncoderTest extends TestCase
{

	public function testPasses(): void
	{
		$raw = 'password';

		$encoder = new BcryptPasswordEncoder();
		$encoded = $encoder->encode($raw);

		self::assertFalse($encoder->needsReEncode($encoded));
		self::assertTrue($encoder->isValid($raw, $encoded));
	}

	public function testParameters(): void
	{
		$raw = '1234';

		$encoder = new BcryptPasswordEncoder(4);
		$encoded = $encoder->encode($raw);

		self::assertFalse($encoder->needsReEncode($encoded));
		self::assertTrue($encoder->isValid($raw, $encoded));
	}

	public function testCostTooLow(): void
	{
		$this->expectException(InvalidArgument::class);
		$this->expectExceptionMessage('Context: Trying to set bcrypt algorithm cost.
Problem: Cost 3 is out of range.
Solution: Choose cost in range 4-31.');

		new BcryptPasswordEncoder(3);
	}

	public function testCostTooHigh(): void
	{
		$this->expectException(InvalidArgument::class);
		$this->expectExceptionMessage('Context: Trying to set bcrypt algorithm cost.
Problem: Cost 32 is out of range.
Solution: Choose cost in range 4-31.');

		new BcryptPasswordEncoder(32);
	}

	/**
	 * @dataProvider providePreGeneratedPasses
	 */
	public function testPreGeneratedPasses(string $raw, string $encoded, bool $needsReEncode): void
	{
		$encoder = new BcryptPasswordEncoder();
		self::assertSame($needsReEncode, $encoder->needsReEncode($encoded));
		self::assertTrue($encoder->isValid($raw, $encoded));
	}

	/**
	 * @return Generator<array<mixed>>
	 */
	public function providePreGeneratedPasses(): Generator
	{
		// Same settings
		yield ['password', '$2y$10$WfjR3j4GPLEYUNPJ/MRw0.UQ3Ar12XSY4XH65XCNUXg04i9tniR6m', false];
		yield ['password', '$2y$10$xBDlCNKL.VklfftzbuNhsOsmvCXxwJnUMfF6tSHUj9mtwFlr0wYCy', false];
		yield ['1234', '$2y$10$T3dU0.qMNbWQedIVK2yPteTpiG5jJC4kNyUiMX2pWnkRrPU34C93O', false];

		// Different settings
		yield ['password', '$2y$09$tD9kmDjFoiws/6ioiR.25uwPuC0Cn9MWPKUn9Uugb5IqA.3HpN8Hq', true];
		yield ['password', '$2y$04$5x2UkDrfwjoV/690Lr3evOeiSNfCiXdGRaqiYszaqimg.317nWbqO', true];
		yield ['1234', '$2y$04$gvdXCt3yOKNBrHRdkFco1.Co27QVcJWsDU17WaYOsJiELr0LI.Mai', true];
	}

	/**
	 * @dataProvider providePreGeneratedNotPasses
	 */
	public function testPreGeneratedNotPasses(string $raw, string $encoded, bool $needsReEncode): void
	{
		$encoder = new BcryptPasswordEncoder();
		self::assertSame($needsReEncode, $encoder->needsReEncode($encoded));
		self::assertFalse($encoder->isValid($raw, $encoded));
	}

	/**
	 * @return Generator<array<mixed>>
	 */
	public function providePreGeneratedNotPasses(): Generator
	{
		// Invalid hash
		yield ['password', '$2y$10$T3dU0.qMNbWQedIVK2yPteTpiG5jJC4kNyUiMX2pWnkRrPU34C93O', false];
		yield ['1234', '$2y$10$xBDlCNKL.VklfftzbuNhsOsmvCXxwJnUMfF6tSHUj9mtwFlr0wYCy', false];

		// Different algorithm
		yield ['password', '$5y$09$tD9kmDjFoiws/6ioiR.25uwPuC0Cn9MWPKUn9Uugb5IqA.3HpN8Hq', true];
		yield ['password', '$argon2id$v=19$m=65536,t=4,p=1$slm91G+ef6aVrd4wCkGqnQ$/czbqSDfBGb6dAkKFvHPX7xDUTo76z1dg/NtC2Pq8/w', true];
		yield ['1234', 'loremipsum', true];
	}

	/**
	 * Test that 72 characters limit of bcrypt is still actual and password is trimmed to 72 chars
	 */
	public function testBcryptCharactersLimit(): void
	{
		$passwordWith72Chars = 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa';
		$passwordWith73Chars = 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa';

		$encoder = new BcryptPasswordEncoder();
		$encoded1 = $encoder->encode($passwordWith72Chars);
		$encoded2 = $encoder->encode($passwordWith73Chars);

		self::assertTrue($encoder->isValid($passwordWith72Chars, $encoded1));
		self::assertTrue($encoder->isValid($passwordWith72Chars, $encoded2));

		self::assertTrue($encoder->isValid($passwordWith73Chars, $encoded1));
		self::assertTrue($encoder->isValid($passwordWith73Chars, $encoded2));

		self::assertFalse($encoder->needsReEncode($encoded1));
		self::assertFalse($encoder->needsReEncode($encoded2));
	}

}
