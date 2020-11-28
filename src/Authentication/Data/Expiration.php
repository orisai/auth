<?php declare(strict_types = 1);

namespace Orisai\Auth\Authentication\Data;

use Brick\DateTime\Duration;
use Brick\DateTime\Instant;

class Expiration
{

	protected Instant $time;
	private Duration $delta;

	public function __construct(Instant $time, Duration $delta)
	{
		$this->time = $time;
		$this->delta = $delta;
	}

	public function getTime(): Instant
	{
		return $this->time;
	}

	public function getDelta(): Duration
	{
		return $this->delta;
	}

	/**
	 * @return array<mixed>
	 */
	public function __serialize(): array
	{
		return [
			'time' => $this->time->getEpochSecond(),
			'delta' => $this->delta->getSeconds(),
		];
	}

	/**
	 * @param array<mixed> $data
	 */
	public function __unserialize(array $data): void
	{
		$this->time = Instant::of($data['time']);
		$this->delta = Duration::ofSeconds($data['delta']);
	}

}
