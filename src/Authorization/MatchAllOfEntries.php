<?php declare(strict_types = 1);

namespace Orisai\Auth\Authorization;

use Orisai\Exceptions\Logic\InvalidArgument;
use function count;

final class MatchAllOfEntries
{

	/** @var list<AccessEntry|MatchAllOfEntries|MatchAnyOfEntries> */
	private array $entries;

	/**
	 * @param list<AccessEntry|MatchAllOfEntries|MatchAnyOfEntries> $entries
	 */
	public function __construct(array $entries)
	{
		if (count($entries) < 2) {
			throw InvalidArgument::create()
				->withMessage('At least 2 entries are required.');
		}

		$this->entries = $entries;
	}

	/**
	 * @return list<AccessEntry|MatchAllOfEntries|MatchAnyOfEntries>
	 */
	public function getEntries(): array
	{
		return $this->entries;
	}

	public function match(): bool
	{
		foreach ($this->entries as $entry) {
			if (!$entry->match()) {
				return false;
			}
		}

		return true;
	}

}
