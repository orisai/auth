<?php declare(strict_types = 1);

namespace Orisai\Auth\Authentication\Exception;

use Orisai\Auth\Authentication\DecisionReason;
use Orisai\Exceptions\DomainException;

final class IdentityExpired extends DomainException
{

	private ?DecisionReason $logoutReasonDescription;

	public static function create(?DecisionReason $logoutReasonDescription = null): self
	{
		$self = new self();
		$self->logoutReasonDescription = $logoutReasonDescription;

		return $self;
	}

	public function getLogoutReasonDescription(): ?DecisionReason
	{
		return $this->logoutReasonDescription;
	}

}
