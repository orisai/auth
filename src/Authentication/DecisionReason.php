<?php declare(strict_types = 1);

namespace Orisai\Auth\Authentication;

use Orisai\Exceptions\Logic\InvalidState;

final class DecisionReason
{

	private string $message;

	/** @var array<int|string, mixed> */
	private array $parameters;

	private bool $translatable;

	/**
	 * @param array<int|string, mixed> $parameters
	 */
	private function __construct(string $message, array $parameters, bool $translatable)
	{
		$this->message = $message;
		$this->parameters = $parameters;
		$this->translatable = $translatable;
	}

	public static function create(string $message): self
	{
		return new self($message, [], false);
	}

	/**
	 * @param array<int|string, mixed> $parameters
	 */
	public static function createTranslatable(string $message, array $parameters): self
	{
		return new self($message, $parameters, true);
	}

	public function getMessage(): string
	{
		return $this->message;
	}

	/**
	 * @return array<int|string, mixed>
	 */
	public function getParameters(): array
	{
		if (!$this->isTranslatable()) {
			throw InvalidState::create()
				->withMessage('Only translatable reason has parameters.');
		}

		return $this->parameters;
	}

	public function isTranslatable(): bool
	{
		return $this->translatable;
	}

	/**
	 * @return array<mixed>
	 */
	public function __serialize(): array
	{
		return [
			'message' => $this->message,
			'parameters' => $this->parameters,
			'translatable' => $this->translatable,
		];
	}

	/**
	 * @param array<mixed> $data
	 */
	public function __unserialize(array $data): void
	{
		$this->message = $data['message'];
		$this->parameters = $data['parameters'];
		$this->translatable = $data['translatable'];
	}

}
