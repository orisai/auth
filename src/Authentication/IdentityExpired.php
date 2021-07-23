<?php declare(strict_types = 1);

namespace Orisai\Auth\Authentication;

use Orisai\Exceptions\DomainException;

final class IdentityExpired extends DomainException
{

	private ?string $logoutReasonDescription;

	public static function create(?string $logoutReasonDescription = null): self
	{
		$self = new self();
		$self->logoutReasonDescription = $logoutReasonDescription;

		return $self;
	}

	public function getLogoutReasonDescription(): ?string
	{
		return $this->logoutReasonDescription;
	}

}
