<?php declare(strict_types = 1);

namespace Tests\Orisai\Auth\Unit\Passwords;

use Generator;
use Orisai\Auth\Passwords\SodiumPasswordHasher;
use Orisai\Utils\Dependencies\DependenciesTester;
use Orisai\Utils\Dependencies\Exception\ExtensionRequired;
use PHPUnit\Framework\TestCase;

final class SodiumPasswordHasherTest extends TestCase
{

	protected function setUp(): void
	{
		parent::setUp();

		if (!SodiumPasswordHasher::isSupported()) {
			self::markTestSkipped('php extension sodium is not installed');
		}
	}

	public function testPasses(): void
	{
		$raw = 'password';

		$hasher = new SodiumPasswordHasher();
		$hashed = $hasher->hash($raw);

		self::assertFalse($hasher->needsRehash($hashed));
		self::assertTrue($hasher->isValid($raw, $hashed));
	}

	public function testParameters(): void
	{
		$raw = 'password';

		$hasher = new SodiumPasswordHasher(3, 10 * 1_024);
		$hashed = $hasher->hash($raw);

		self::assertFalse($hasher->needsRehash($hashed));
		self::assertTrue($hasher->isValid($raw, $hashed));
	}

	/**
	 * @dataProvider providePreGeneratedPasses
	 */
	public function testPreGeneratedPasses(string $raw, string $hashed, bool $needsRehash): void
	{
		$hasher = new SodiumPasswordHasher();
		self::assertSame($needsRehash, $hasher->needsRehash($hashed));
		self::assertTrue($hasher->isValid($raw, $hashed));
	}

	/**
	 * @return Generator<array<mixed>>
	 */
	public function providePreGeneratedPasses(): Generator
	{
		// Same settings
		yield ['password', '$argon2id$v=19$m=65536,t=4,p=1$FAVkaIWcsmaiBc5rPjHkQQ$vFWkqcLV0q1aXneWvrp4w0m35xZrSJyB7yHh5By4FsE', false];
		yield ['password', '$argon2id$v=19$m=65536,t=4,p=1$TVhGnWEIR0E3q3CHEf0ZmQ$jtEtQDEP9SIs4r4x84ELG3DOEqB20d+M+cP6Z+J3bOQ', false];
		yield ['1234', '$argon2id$v=19$m=65536,t=4,p=1$JX8zPDMpDk/MYdcwfOHIRw$BUOtILBXRuJqE2QnurzBwnIrU0pCIhU0XN5pPcVTKnM', false];

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
		$hasher = new SodiumPasswordHasher();
		self::assertSame($needsRehash, $hasher->needsRehash($hashed));
		self::assertFalse($hasher->isValid($raw, $hashed));
	}

	/**
	 * @return Generator<array<mixed>>
	 */
	public function providePreGeneratedNotPasses(): Generator
	{
		// Invalid hash
		yield ['password', '$argon2id$v=19$m=65536,t=4,p=1$JX8zPDMpDk/MYdcwfOHIRw$BUOtILBXRuJqE2QnurzBwnIrU0pCIhU0XN5pPcVTKnM', false];
		yield ['1234', '$argon2id$v=19$m=65536,t=4,p=1$FAVkaIWcsmaiBc5rPjHkQQ$vFWkqcLV0q1aXneWvrp4w0m35xZrSJyB7yHh5By4FsE', false];

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
			new SodiumPasswordHasher();
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
