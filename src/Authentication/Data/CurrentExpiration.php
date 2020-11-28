<?php declare(strict_types = 1);

namespace Orisai\Auth\Authentication\Data;

use Brick\DateTime\Instant;

final class CurrentExpiration extends Expiration
{

	public function setTime(Instant $time): void
	{
		$this->time = $time;
	}

}
