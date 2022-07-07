<?php declare(strict_types = 1);

namespace Tests\Orisai\Auth\Unit\Passwords;

use Generator;
use Orisai\Auth\Passwords\Argon2PasswordHasher;
use Orisai\Utils\Dependencies\DependenciesTester;
use Orisai\Utils\Dependencies\Exception\ExtensionRequired;
use PHPUnit\Framework\TestCase;

final class Argon2PasswordHasherTest extends TestCase
{

	protected function setUp(): void
	{
		parent::setUp();

		if (!Argon2PasswordHasher::isSupported()) {
			self::markTestSkipped('php extension sodium is not installed');
		}
	}

	public function testPasses(): void
	{
		$raw = 'password';

		$hasher = new Argon2PasswordHasher();
		$hashed = $hasher->hash($raw);

		self::assertFalse($hasher->needsRehash($hashed));
		self::assertTrue($hasher->isValid($raw, $hashed));
	}

	public function testParameters(): void
	{
		$raw = 'password';

		$hasher = new Argon2PasswordHasher(2, 8, 1);
		$hashed = $hasher->hash($raw);

		self::assertStringStartsWith('$argon2id$v=19$m=8,t=2,p=1$', $hashed);
		self::assertFalse($hasher->needsRehash($hashed));
		self::assertTrue($hasher->isValid($raw, $hashed));

		$hasher = new Argon2PasswordHasher();
		$hashed = $hasher->hash($raw);

		self::assertStringStartsWith('$argon2id$v=19$m=65536,t=16,p=4$', $hashed);
		self::assertFalse($hasher->needsRehash($hashed));
		self::assertTrue($hasher->isValid($raw, $hashed));
	}

	/**
	 * @dataProvider providePreGeneratedPasses
	 */
	public function testPreGeneratedPasses(string $raw, string $hashed, bool $needsRehash): void
	{
		$hasher = new Argon2PasswordHasher(16, 15_000, 2);
		self::assertSame($needsRehash, $hasher->needsRehash($hashed));
		self::assertTrue($hasher->isValid($raw, $hashed));
	}

	/**
	 * @return Generator<array<mixed>>
	 */
	public function providePreGeneratedPasses(): Generator
	{
		// Same settings
		yield ['password', '$argon2id$v=19$m=15000,t=16,p=2$Yi84WUhFNFdzSC9JR1UvcA$Kqz4eoD7hmu94v4gDa7ZN50ECZ4CJM8oRLcAsWwcDIU', false];
		yield ['password', '$argon2id$v=19$m=15000,t=16,p=2$QXh2emouc01VLzVXWjFiRg$J/2jz5+bE0tSOuke3dDK3qrEz37yjJZTc0EwbYOg8JI', false];
		yield ['1234', '$argon2id$v=19$m=15000,t=16,p=2$TWpCbkcvNFFFQzk2Ty5Oeg$dWdAsFvWuIF3ESleRBh6Kl0zItNkij47crqmj7z2zlo', false];

		// Different settings
		yield ['password', '$argon2id$v=19$m=10,t=3,p=1$aM3h+Sq0LVbxdB/LNrL3hA$pd0VCPIAmMpJH4CbsaFpvzFhK0YMzK2aZYkin+sTR74', true];
		yield ['password', '$argon2id$v=19$m=10,t=3,p=1$Fhr579lWSjFfQUZvRDd3LQ$b/aCEImCQavonjeFA7cQJx+Ajq04v4O1sZhxC1sHyCM', true];
		yield ['1234', '$argon2id$v=19$m=10,t=3,p=1$e359GWq64GpFSbIbldlE/Q$IdsVgan5ZGm1Cxds+GxhniMVNJDbDVEf2Yvf2ujnZb8', true];
	}

	/**
	 * @dataProvider providePreGeneratedNotPasses
	 */
	public function testPreGeneratedNotPasses(string $raw, string $hashed, bool $needsRehash): void
	{
		$hasher = new Argon2PasswordHasher(16, 15_000, 2);
		self::assertSame($needsRehash, $hasher->needsRehash($hashed));
		self::assertFalse($hasher->isValid($raw, $hashed));
	}

	/**
	 * @return Generator<array<mixed>>
	 */
	public function providePreGeneratedNotPasses(): Generator
	{
		// Invalid hash
		yield ['password', '$argon2id$v=19$m=15000,t=16,p=2$JX8zPDMpDk/MYdcwfOHIRw$BUOtILBXRuJqE2QnurzBwnIrU0pCIhU0XN5pPcVTKnM', false];
		yield ['1234', '$argon2id$v=19$m=15000,t=16,p=2$FAVkaIWcsmaiBc5rPjHkQQ$vFWkqcLV0q1aXneWvrp4w0m35xZrSJyB7yHh5By4FsE', false];

		// Different algorithm
		yield ['password', '$5y$09$tD9kmDjFoiws/6ioiR.25uwPuC0Cn9MWPKUn9Uugb5IqA.3HpN8Hq', true];
		yield ['password', '$2y$10$WfjR3j4GPLEYUNPJ/MRw0.UQ3Ar12XSY4XH65XCNUXg04i9tniR6m', true];
		yield ['1234', 'loremipsum', true];
	}

	/**
	 * @runInSeparateProcess
	 */
	public function testOptionalDependencies(): void
	{
		DependenciesTester::addIgnoredExtensions(['sodium']);

		$exception = null;

		try {
			new Argon2PasswordHasher();
		} catch (ExtensionRequired $exception) {
			// Handled below
		}

		self::assertNotNull($exception);
		self::assertSame(
			['sodium'],
			$exception->getExtensions(),
		);
	}

}
