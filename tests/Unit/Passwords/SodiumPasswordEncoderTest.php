<?php declare(strict_types = 1);

namespace Tests\Orisai\Auth\Unit\Passwords;

use Generator;
use Orisai\Auth\Passwords\SodiumPasswordEncoder;
use Orisai\Exceptions\Logic\InvalidArgument;
use PHPUnit\Framework\TestCase;

final class SodiumPasswordEncoderTest extends TestCase
{

	protected function setUp(): void
	{
		parent::setUp();

		if (!SodiumPasswordEncoder::isSupported()) {
			self::markTestSkipped('php extension sodium is not installed');
		}
	}

	public function testPasses(): void
	{
		$raw = 'password';

		$encoder = new SodiumPasswordEncoder();
		$encoded = $encoder->encode($raw);

		self::assertFalse($encoder->needsReEncode($encoded));
		self::assertTrue($encoder->isValid($raw, $encoded));
	}

	public function testParameters(): void
	{
		$raw = 'password';

		$encoder = new SodiumPasswordEncoder(3, 10 * 1_024);
		$encoded = $encoder->encode($raw);

		self::assertFalse($encoder->needsReEncode($encoded));
		self::assertTrue($encoder->isValid($raw, $encoded));
	}

	public function testTimeCostTooLow(): void
	{
		$this->expectException(InvalidArgument::class);
		$this->expectExceptionMessage('Context: Trying to set argon2 algorithm time cost.
Problem: Cost 2 is too low.
Solution: Choose cost 3 or greater.');

		new SodiumPasswordEncoder(2);
	}

	public function testMemoryCostTooLow(): void
	{
		$this->expectException(InvalidArgument::class);
		$this->expectExceptionMessage('Context: Trying to set argon2 algorithm memory cost.
Problem: Cost 10 is too low.
Solution: Choose cost 10240 or greater (in bytes).');

		new SodiumPasswordEncoder(null, 10);
	}

	/**
	 * @dataProvider providePreGeneratedPasses
	 */
	public function testPreGeneratedPasses(string $raw, string $encoded, bool $needsReEncode): void
	{
		$encoder = new SodiumPasswordEncoder();
		self::assertSame($needsReEncode, $encoder->needsReEncode($encoded));
		self::assertTrue($encoder->isValid($raw, $encoded));
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
	public function testPreGeneratedNotPasses(string $raw, string $encoded, bool $needsReEncode): void
	{
		$encoder = new SodiumPasswordEncoder();
		self::assertSame($needsReEncode, $encoder->needsReEncode($encoded));
		self::assertFalse($encoder->isValid($raw, $encoded));
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

}
