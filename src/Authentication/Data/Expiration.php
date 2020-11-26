<?php declare(strict_types = 1);

namespace Orisai\Auth\Authentication\Data;

class Expiration
{

	protected int $timestamp;
	private int $delta;

	public function __construct(int $timestamp, int $delta)
	{
		$this->timestamp = $timestamp;
		$this->delta = $delta;
	}

	public function getTimestamp(): int
	{
		return $this->timestamp;
	}

	public function getDelta(): int
	{
		return $this->delta;
	}

	/**
	 * @return array<mixed>
	 */
	public function __serialize(): array
	{
		return [
			'timestamp' => $this->timestamp,
			'delta' => $this->delta,
		];
	}

	/**
	 * @param array<mixed> $data
	 */
	public function __unserialize(array $data): void
	{
		$this->timestamp = $data['timestamp'];
		$this->delta = $data['delta'];
	}

}
