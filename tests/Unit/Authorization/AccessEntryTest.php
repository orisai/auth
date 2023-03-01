<?php declare(strict_types = 1);

namespace Tests\Orisai\Auth\Unit\Authorization;

use Generator;
use Orisai\Auth\Authorization\AccessEntry;
use Orisai\Auth\Authorization\AccessEntryResult;
use Orisai\Auth\Authorization\MatchAllOfEntries;
use Orisai\Auth\Authorization\MatchAnyOfEntries;
use Orisai\TranslationContracts\TranslatableMessage;
use PHPUnit\Framework\TestCase;

final class AccessEntryTest extends TestCase
{

	public function test(): void
	{
		$message = 'Message';
		$entry = new AccessEntry(AccessEntryResult::allowed(), $message);

		self::assertSame(AccessEntryResult::allowed(), $entry->getResult());
		self::assertSame($message, $entry->getMessage());
	}

	public function testTranslatable(): void
	{
		$message = new TranslatableMessage('translatable.message', ['a' => 'b']);
		$entry = new AccessEntry(AccessEntryResult::forbidden(), $message);

		self::assertSame(AccessEntryResult::forbidden(), $entry->getResult());
		self::assertSame($message, $entry->getMessage());
	}

	/**
	 * @dataProvider provideMatch
	 */
	public function testMatch(bool $match, AccessEntry $entry): void
	{
		self::assertSame($match, $entry->match());
	}

	public function provideMatch(): Generator
	{
		yield [
			true,
			new AccessEntry(AccessEntryResult::allowed(), ''),
		];

		yield [
			false,
			new AccessEntry(AccessEntryResult::forbidden(), ''),
		];

		yield [
			false,
			new AccessEntry(AccessEntryResult::skipped(), ''),
		];
	}

	public function testConstructors(): void
	{
		$entries = [
			new AccessEntry(AccessEntryResult::allowed(), ''),
			new AccessEntry(AccessEntryResult::forbidden(), ''),
			new AccessEntry(AccessEntryResult::skipped(), ''),
		];

		$all = AccessEntry::matchAll($entries);
		self::assertEquals(new MatchAllOfEntries($entries), $all);

		$any = AccessEntry::matchAny($entries);
		self::assertEquals(new MatchAnyOfEntries($entries), $any);
	}

	public function testForRequiredPrivilege(): void
	{
		$result = AccessEntryResult::allowed();
		$privilege = 'privilege';
		$entry = AccessEntry::forRequiredPrivilege($result, $privilege);

		self::assertSame($result, $entry->getResult());
		self::assertEquals(
			new TranslatableMessage('orisai.auth.entry.requiredPrivilege', [
				'privilege' => $privilege,
			]),
			$entry->getMessage(),
		);
	}

}
