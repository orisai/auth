<?php declare(strict_types = 1);

namespace Orisai\Auth\Authorization;

use Orisai\Auth\Authentication\Data\ExpiredLogin;
use Orisai\Auth\Authentication\DecisionReason;
use Orisai\Auth\Authentication\Firewall;
use Orisai\Auth\Authentication\Identity;

final class CurrentUserPolicyContext implements PolicyContext
{

	private Authorizer $authorizer;

	/** @var Firewall<Identity> */
	private Firewall $firewall;

	private ?DecisionReason $decisionReason = null;

	/**
	 * @param Firewall<Identity> $firewall
	 *
	 * @internal
	 */
	public function __construct(Firewall $firewall)
	{
		$this->authorizer = $firewall->getAuthorizer();
		$this->firewall = $firewall;
	}

	public function getAuthorizer(): Authorizer
	{
		return $this->authorizer;
	}

	/**
	 * @return array<ExpiredLogin>
	 */
	public function getExpiredLogins(): array
	{
		return $this->firewall->getExpiredLogins();
	}

	public function setDecisionReason(DecisionReason $reason): void
	{
		$this->decisionReason = $reason;
	}

	public function getDecisionReason(): ?DecisionReason
	{
		return $this->decisionReason;
	}

}
