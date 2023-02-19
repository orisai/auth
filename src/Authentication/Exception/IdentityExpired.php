<?php declare(strict_types = 1);

namespace Orisai\Auth\Authentication\Exception;

use Orisai\Exceptions\DomainException;
use Orisai\TranslationContracts\TranslatableMessage;

final class IdentityExpired extends DomainException
{

	/** @var string|TranslatableMessage|null */
	private $logoutReason;

	/**
	 * @param string|TranslatableMessage|null $logoutReason
	 */
	public static function create($logoutReason = null): self
	{
		$self = new self();
		$self->logoutReason = $logoutReason;

		return $self;
	}

	/**
	 * @return string|TranslatableMessage|null
	 */
	public function getLogoutReason()
	{
		return $this->logoutReason;
	}

}
