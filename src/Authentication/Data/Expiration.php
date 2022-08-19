<?php declare(strict_types = 1);

namespace Orisai\Auth\Authentication\Data;

use DateTimeImmutable;

class Expiration
{

	protected DateTimeImmutable $time;

	private int $delta;

	public function __construct(DateTimeImmutable $time, int $delta)
	{
		$this->time = $time;
		$this->delta = $delta;
	}

	public function getTime(): DateTimeImmutable
	{
		return $this->time;
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
			'time' => $this->time->getTimestamp(),
			'delta' => $this->delta,
		];
	}

	/**
	 * @param array<mixed> $data
	 */
	public function __unserialize(array $data): void
	{
		$this->time = DateTimeImmutable::createFromFormat('U', (string) $data['time']);
		$this->delta = $data['delta'];
	}

}
