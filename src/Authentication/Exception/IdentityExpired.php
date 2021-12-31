<?php declare(strict_types = 1);

namespace Orisai\Auth\Authentication\Exception;

use Orisai\Auth\Authentication\DecisionReason;
use Orisai\Exceptions\DomainException;

final class IdentityExpired extends DomainException
{

	private ?DecisionReason $logoutReason;

	public static function create(?DecisionReason $logoutReason = null): self
	{
		$self = new self();
		$self->logoutReason = $logoutReason;

		return $self;
	}

	public function getLogoutReason(): ?DecisionReason
	{
		return $this->logoutReason;
	}

}
