<?php declare(strict_types = 1);

namespace Orisai\Auth\Authorization;

use Orisai\TranslationContracts\Translatable;

final class AccessEntry
{

	private AccessEntryType $type;

	/** @var string|Translatable */
	private $message;

	/**
	 * @param string|Translatable $message
	 */
	public function __construct(AccessEntryType $type, $message)
	{
		$this->type = $type;
		$this->message = $message;
	}

	public function getType(): AccessEntryType
	{
		return $this->type;
	}

	/**
	 * @return string|Translatable
	 */
	public function getMessage()
	{
		return $this->message;
	}

}
