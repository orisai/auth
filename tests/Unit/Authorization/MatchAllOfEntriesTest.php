<?php declare(strict_types = 1);

namespace Tests\Orisai\Auth\Unit\Authorization;

use Generator;
use Orisai\Auth\Authorization\AccessEntry;
use Orisai\Auth\Authorization\AccessEntryResult;
use Orisai\Auth\Authorization\MatchAllOfEntries;
use Orisai\Auth\Authorization\MatchAnyOfEntries;
use Orisai\Exceptions\Logic\InvalidArgument;
use PHPUnit\Framework\TestCase;

final class MatchAllOfEntriesTest extends TestCase
{

	/**
	 * @param list<AccessEntry|MatchAllOfEntries|MatchAnyOfEntries> $entries
	 *
	 * @dataProvider provide
	 */
	public function test(bool $match, array $entries): void
	{
		$entry = new MatchAllOfEntries($entries);
		self::assertSame($entries, $entry->getEntries());
		self::assertSame($match, $entry->match());
	}

	public function provide(): Generator
	{
		yield [
			true,
			[
				new AccessEntry(AccessEntryResult::allowed(), ''),
				new AccessEntry(AccessEntryResult::allowed(), ''),
			],
		];

		yield [
			false,
			[
				new AccessEntry(AccessEntryResult::allowed(), ''),
				new AccessEntry(AccessEntryResult::forbidden(), ''),
			],
		];

		yield [
			false,
			[
				new AccessEntry(AccessEntryResult::allowed(), ''),
				new AccessEntry(AccessEntryResult::skipped(), ''),
			],
		];

		yield [
			false,
			[
				new AccessEntry(AccessEntryResult::forbidden(), ''),
				new AccessEntry(AccessEntryResult::allowed(), ''),
			],
		];

		yield [
			false,
			[
				new AccessEntry(AccessEntryResult::forbidden(), ''),
				new AccessEntry(AccessEntryResult::skipped(), ''),
			],
		];

		yield [
			true,
			[
				new AccessEntry(AccessEntryResult::allowed(), ''),
				new AccessEntry(AccessEntryResult::allowed(), ''),
				new AccessEntry(AccessEntryResult::allowed(), ''),
			],
		];

		yield [
			false,
			[
				new AccessEntry(AccessEntryResult::forbidden(), ''),
				new AccessEntry(AccessEntryResult::skipped(), ''),
				new AccessEntry(AccessEntryResult::forbidden(), ''),
			],
		];

		yield [
			true,
			[
				new AccessEntry(AccessEntryResult::allowed(), ''),
				new MatchAllOfEntries([
					new AccessEntry(AccessEntryResult::allowed(), ''),
					new AccessEntry(AccessEntryResult::allowed(), ''),
				]),
			],
		];

		yield [
			false,
			[
				new AccessEntry(AccessEntryResult::allowed(), ''),
				new MatchAllOfEntries([
					new AccessEntry(AccessEntryResult::allowed(), ''),
					new AccessEntry(AccessEntryResult::forbidden(), ''),
				]),
			],
		];

		yield [
			true,
			[
				new AccessEntry(AccessEntryResult::allowed(), ''),
				new MatchAnyOfEntries([
					new AccessEntry(AccessEntryResult::allowed(), ''),
					new AccessEntry(AccessEntryResult::forbidden(), ''),
				]),
			],
		];

		yield [
			false,
			[
				new AccessEntry(AccessEntryResult::allowed(), ''),
				new MatchAnyOfEntries([
					new AccessEntry(AccessEntryResult::forbidden(), ''),
					new AccessEntry(AccessEntryResult::forbidden(), ''),
				]),
			],
		];
	}

	public function testNotEnoughEntries(): void
	{
		$this->expectException(InvalidArgument::class);
		$this->expectExceptionMessage('At least 2 entries are required.');

		new MatchAllOfEntries([
			new AccessEntry(AccessEntryResult::allowed(), ''),
		]);
	}

}
