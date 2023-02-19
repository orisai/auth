<?php declare(strict_types = 1);

namespace Tests\Orisai\Auth\Doubles;

use Orisai\Auth\Authentication\Exception\IdentityExpired;
use Orisai\Auth\Authentication\Identity;
use Orisai\Auth\Authentication\IdentityRefresher;
use Orisai\TranslationContracts\Translatable;

/**
 * @phpstan-implements IdentityRefresher<Identity>
 */
final class NeverPassIdentityRefresher implements IdentityRefresher
{

	/** @var string|Translatable|null */
	private $reason;

	/**
	 * @param string|Translatable|null $reason
	 */
	public function __construct($reason = null)
	{
		$this->reason = $reason;
	}

	public function refresh(Identity $identity): Identity
	{
		throw IdentityExpired::create($this->reason);
	}

}
