<?php declare(strict_types = 1);

namespace Orisai\Auth\Authorization;

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
		return $this->parameters;
	}

	public function isTranslatable(): bool
	{
		return $this->translatable;
	}

}
