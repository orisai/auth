<?php declare(strict_types = 1);

namespace Orisai\Auth\Authentication;

use Orisai\TranslationContracts\Translatable;
use Orisai\TranslationContracts\TranslatableMessage;

final class DecisionReason
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

	/**
	 * @return array<mixed>
	 */
	public function __serialize(): array
	{
		return [
			'message' => $this->message,
		];
	}

	/**
	 * @param array<mixed> $data
	 */
	public function __unserialize(array $data): void
	{
		// Compatibility
		if (isset($data['parameters'], $data['translatable'])) {
			$message = $data['translatable'] === true
				? new TranslatableMessage($data['message'], $data['parameters'])
				: $data['message'];
		} else {
			$message = $data['message'];
		}

		$this->message = $message;
	}

}
