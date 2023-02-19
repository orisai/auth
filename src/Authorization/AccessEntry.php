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

}
