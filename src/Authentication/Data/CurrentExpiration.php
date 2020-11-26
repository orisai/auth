<?php declare(strict_types = 1);

namespace Orisai\Auth\Authentication\Data;

final class CurrentExpiration extends Expiration
{

	public function setTimestamp(int $timestamp): void
	{
		$this->timestamp = $timestamp;
	}

}
