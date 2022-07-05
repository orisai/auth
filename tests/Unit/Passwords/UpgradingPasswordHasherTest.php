<?php declare(strict_types = 1);

namespace Tests\Orisai\Auth\Unit\Passwords;

use Orisai\Auth\Passwords\BcryptPasswordHasher;
use Orisai\Auth\Passwords\UpgradingPasswordHasher;
use PHPUnit\Framework\TestCase;
use Tests\Orisai\Auth\Doubles\StaticListPasswordHasher;

final class UpgradingPasswordHasherTest extends TestCase
{

	public function testPasses(): void
	{
		$preferred = new StaticListPasswordHasher();
		$rawPreferred = 'preferred';
		$hashedPreferred = $preferred->hash($rawPreferred);

		$outdated1 = new StaticListPasswordHasher();
		$rawOutdated1 = 'outdated1';
		$hashedOutdated1 = $outdated1->hash($rawOutdated1);

		$outdated2 = new StaticListPasswordHasher();
		$rawOutdated2 = 'outdated2';
		$hashedOutdated2 = $outdated2->hash($rawOutdated2);

		$hasher = new UpgradingPasswordHasher($preferred, [$outdated1, $outdated2]);
		$rawHasher = 'password';
		$hashedHasher = $hasher->hash($rawHasher);

		// Preferred hasher
		self::assertFalse($hasher->needsRehash($hashedHasher));
		self::assertTrue($hasher->isValid($rawHasher, $hashedHasher));

		self::assertFalse($hasher->needsRehash($hashedPreferred));
		self::assertTrue($hasher->isValid($rawPreferred, $hashedPreferred));

		// Outdated 1 hasher
		self::assertTrue($hasher->needsRehash($hashedOutdated1));
		self::assertTrue($hasher->isValid($rawOutdated1, $hashedOutdated1));

		// Outdated 2 hasher
		self::assertTrue($hasher->needsRehash($hashedOutdated2));
		self::assertTrue($hasher->isValid($rawOutdated2, $hashedOutdated2));

		// password_verify fallback
		self::assertTrue($hasher->isValid('1234', '$2y$10$T3dU0.qMNbWQedIVK2yPteTpiG5jJC4kNyUiMX2pWnkRrPU34C93O'));
		self::assertFalse($hasher->isValid('5678', '$2y$10$T3dU0.qMNbWQedIVK2yPteTpiG5jJC4kNyUiMX2pWnkRrPU34C93O'));
	}

	public function testNotPasses(): void
	{
		$hasher = new UpgradingPasswordHasher(new StaticListPasswordHasher(), [new StaticListPasswordHasher()]);

		self::assertTrue($hasher->needsRehash('random_string'));
		self::assertFalse($hasher->isValid('random_string', 'hashed_random_string'));
	}

	public function testNeedsRehash(): void
	{
		$bcryptHasher = new BcryptPasswordHasher(4);
		$hasher = new UpgradingPasswordHasher($bcryptHasher);

		// Does not need rehash, is just invalid
		self::assertFalse($hasher->isValid('1234', '$2y$04$5x2UkDrfwjoV/690Lr3evOeiSNfCiXdGRaqiYszaqimg.317nWbqO'));

		// Is valid, needs rehash
		self::assertTrue(
			$hasher->isValid(
				'password',
				'$argon2id$v=19$m=10,t=3,p=1$aM3h+Sq0LVbxdB/LNrL3hA$pd0VCPIAmMpJH4CbsaFpvzFhK0YMzK2aZYkin+sTR74',
			),
		);
	}

}
