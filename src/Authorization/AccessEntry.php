<?php declare(strict_types = 1);

namespace Orisai\Auth\Authorization;

use Orisai\TranslationContracts\Translatable;

final class AccessEntry
{

	private AccessEntryResult $result;

	/** @var string|Translatable */
	private $message;

	/**
	 * @param string|Translatable $message
	 */
	public function __construct(AccessEntryResult $result, $message)
	{
		$this->result = $result;
		$this->message = $message;
	}

	public function getResult(): AccessEntryResult
	{
		return $this->result;
	}

	/**
	 * @return string|Translatable
	 */
	public function getMessage()
	{
		return $this->message;
	}

	/**
	 * @param list<AccessEntry|MatchAllOfEntries|MatchAnyOfEntries> $entries
	 */
	public static function matchAny(array $entries): MatchAnyOfEntries
	{
		return new MatchAnyOfEntries($entries);
	}

	/**
	 * @param list<AccessEntry|MatchAllOfEntries|MatchAnyOfEntries> $entries
	 */
	public static function matchAll(array $entries): MatchAllOfEntries
	{
		return new MatchAllOfEntries($entries);
	}

	public function match(): bool
	{
		return $this->result === AccessEntryResult::allowed();
	}

}
