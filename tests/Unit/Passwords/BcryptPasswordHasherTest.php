<?php declare(strict_types = 1);

namespace Tests\Orisai\Auth\Unit\Passwords;

use Generator;
use Orisai\Auth\Passwords\BcryptPasswordHasher;
use PHPUnit\Framework\TestCase;

final class BcryptPasswordHasherTest extends TestCase
{

	public function testPasses(): void
	{
		$raw = 'password';

		$hasher = new BcryptPasswordHasher();
		$hashed = $hasher->hash($raw);

		self::assertFalse($hasher->needsRehash($hashed));
		self::assertTrue($hasher->isValid($raw, $hashed));
	}

	public function testParameters(): void
	{
		$raw = '1234';

		$hasher = new BcryptPasswordHasher(4);
		$hashed = $hasher->hash($raw);
		self::assertStringStartsWith('$2y$04$', $hashed);
		self::assertFalse($hasher->needsRehash($hashed));
		self::assertTrue($hasher->isValid($raw, $hashed));

		$hasher = new BcryptPasswordHasher();
		$hashed = $hasher->hash($raw);
		self::assertStringStartsWith('$2y$10$', $hashed);
		self::assertFalse($hasher->needsRehash($hashed));
		self::assertTrue($hasher->isValid($raw, $hashed));
	}

	/**
	 * @dataProvider providePreGeneratedPasses
	 */
	public function testPreGeneratedPasses(string $raw, string $hashed, bool $needsRehash): void
	{
		$hasher = new BcryptPasswordHasher();
		self::assertSame($needsRehash, $hasher->needsRehash($hashed));
		self::assertTrue($hasher->isValid($raw, $hashed));
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
	public function testPreGeneratedNotPasses(string $raw, string $hashed, bool $needsRehash): void
	{
		$hasher = new BcryptPasswordHasher();
		self::assertSame($needsRehash, $hasher->needsRehash($hashed));
		self::assertFalse($hasher->isValid($raw, $hashed));
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

		$hasher = new BcryptPasswordHasher();
		$hashed1 = $hasher->hash($passwordWith72Chars);
		$hashed2 = $hasher->hash($passwordWith73Chars);

		self::assertTrue($hasher->isValid($passwordWith72Chars, $hashed1));
		self::assertTrue($hasher->isValid($passwordWith72Chars, $hashed2));

		self::assertTrue($hasher->isValid($passwordWith73Chars, $hashed1));
		self::assertTrue($hasher->isValid($passwordWith73Chars, $hashed2));

		self::assertFalse($hasher->needsRehash($hashed1));
		self::assertFalse($hasher->needsRehash($hashed2));
	}

}
