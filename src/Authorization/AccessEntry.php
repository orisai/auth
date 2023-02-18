<?php declare(strict_types = 1);

namespace Orisai\Auth\Authorization;

use Orisai\TranslationContracts\Translatable;

final class AccessEntry
{

	/** @var string|Translatable */
	private $message;

	/**
	 * @param string|Translatable $message
	 */
	public function __construct($message)
	{
		$this->message = $message;
	}

	/**
	 * @return string|Translatable
	 */
	public function getMessage()
	{
		return $this->message;
	}

}
