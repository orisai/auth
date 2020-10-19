<?php declare(strict_types = 1);

namespace Tests\Orisai\Auth\Unit\Passwords;

use Orisai\Auth\Passwords\UpgradingPasswordEncoder;
use PHPUnit\Framework\TestCase;
use Tests\Orisai\Auth\Doubles\StaticListPasswordEncoder;

final class UpgradingPasswordEncoderTest extends TestCase
{

	public function testPasses(): void
	{
		$preferred = new StaticListPasswordEncoder();
		$rawPreferred = 'preferred';
		$encodedPreferred = $preferred->encode($rawPreferred);

		$outdated1 = new StaticListPasswordEncoder();
		$rawOutdated1 = 'outdated1';
		$encodedOutdated1 = $outdated1->encode($rawOutdated1);

		$outdated2 = new StaticListPasswordEncoder();
		$rawOutdated2 = 'outdated2';
		$encodedOutdated2 = $outdated2->encode($rawOutdated2);

		$encoder = new UpgradingPasswordEncoder($preferred, [$outdated1, $outdated2]);
		$rawEncoder = 'password';
		$encodedEncoder = $encoder->encode($rawEncoder);

		// Preferred encoder
		self::assertFalse($encoder->needsReEncode($encodedEncoder));
		self::assertTrue($encoder->isValid($rawEncoder, $encodedEncoder));

		self::assertFalse($encoder->needsReEncode($encodedPreferred));
		self::assertTrue($encoder->isValid($rawPreferred, $encodedPreferred));

		// Outdated 1 encoder
		self::assertTrue($encoder->needsReEncode($encodedOutdated1));
		self::assertTrue($encoder->isValid($rawOutdated1, $encodedOutdated1));

		// Outdated 2 encoder
		self::assertTrue($encoder->needsReEncode($encodedOutdated2));
		self::assertTrue($encoder->isValid($rawOutdated2, $encodedOutdated2));

		// password_verify fallback
		self::assertTrue($encoder->isValid('1234', '$2y$10$T3dU0.qMNbWQedIVK2yPteTpiG5jJC4kNyUiMX2pWnkRrPU34C93O'));
		self::assertFalse($encoder->isValid('5678', '$2y$10$T3dU0.qMNbWQedIVK2yPteTpiG5jJC4kNyUiMX2pWnkRrPU34C93O'));
	}

	public function testNotPasses(): void
	{
		$encoder = new UpgradingPasswordEncoder(new StaticListPasswordEncoder(), [new StaticListPasswordEncoder()]);

		self::assertTrue($encoder->needsReEncode('random_string'));
		self::assertFalse($encoder->isValid('random_string', 'encoded_random_string'));
	}

}
