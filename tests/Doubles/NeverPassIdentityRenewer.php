<?php declare(strict_types = 1);

namespace Tests\Orisai\Auth\Doubles;

use Orisai\Auth\Authentication\DecisionReason;
use Orisai\Auth\Authentication\Exception\IdentityExpired;
use Orisai\Auth\Authentication\Identity;
use Orisai\Auth\Authentication\IdentityRenewer;

/**
 * @phpstan-implements IdentityRenewer<Identity>
 */
final class NeverPassIdentityRenewer implements IdentityRenewer
{

	private ?DecisionReason $reason;

	public function __construct(?DecisionReason $reason = null)
	{
		$this->reason = $reason;
	}

	public function renewIdentity(Identity $identity): Identity
	{
		throw IdentityExpired::create($this->reason);
	}

}
