<?php declare(strict_types = 1);

namespace Tests\Orisai\Auth\Doubles;

use Orisai\Auth\Authorization\AccessEntry;
use Orisai\Auth\Authorization\MatchAllOfEntries;
use Orisai\Auth\Authorization\MatchAnyOfEntries;

final class EntriesFromContext
{

	/** @var list<AccessEntry|MatchAllOfEntries|MatchAnyOfEntries> */
	public array $entries;

	/**
	 * @param list<AccessEntry|MatchAllOfEntries|MatchAnyOfEntries> $entries
	 */
	public function __construct(array $entries)
	{
		$this->entries = $entries;
	}

}
