<?php declare(strict_types = 1);

namespace Orisai\Auth\Authentication\Data;

use DateTimeImmutable;

final class CurrentExpiration extends Expiration
{

	public function setTime(DateTimeImmutable $time): void
	{
		$this->time = $time;
	}

}
