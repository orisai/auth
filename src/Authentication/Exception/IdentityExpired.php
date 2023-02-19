<?php declare(strict_types = 1);

namespace Orisai\Auth\Authentication\Exception;

use Orisai\Exceptions\DomainException;
use Orisai\TranslationContracts\Translatable;

final class IdentityExpired extends DomainException
{

	/** @var string|Translatable|null */
	private $logoutReason;

	/**
	 * @param string|Translatable|null $logoutReason
	 */
	public static function create($logoutReason = null): self
	{
		$self = new self();
		$self->logoutReason = $logoutReason;

		return $self;
	}

	/**
	 * @return string|Translatable|null
	 */
	public function getLogoutReason()
	{
		return $this->logoutReason;
	}

}
