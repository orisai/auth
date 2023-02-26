<?php declare(strict_types = 1);

namespace Tests\Orisai\Auth\Doubles;

use Orisai\Auth\Authentication\Exception\IdentityExpired;
use Orisai\Auth\Authentication\Identity;
use Orisai\Auth\Authentication\IdentityRefresher;
use Orisai\TranslationContracts\TranslatableMessage;

/**
 * @implements IdentityRefresher<Identity>
 */
final class NeverPassIdentityRefresher implements IdentityRefresher
{

	/** @var string|TranslatableMessage|null */
	private $reason;

	/**
	 * @param string|TranslatableMessage|null $reason
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
