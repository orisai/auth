<?php declare(strict_types = 1);

namespace Orisai\Auth\Authorization;

use Orisai\Auth\Authentication\DecisionReason;

final class AnyUserPolicyContext implements PolicyContext
{

	private Authorizer $authorizer;

	private ?DecisionReason $decisionReason = null;

	/**
	 * @internal
	 */
	public function __construct(Authorizer $authorizer)
	{
		$this->authorizer = $authorizer;
	}

	public function getAuthorizer(): Authorizer
	{
		return $this->authorizer;
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
