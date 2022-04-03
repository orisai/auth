<?php declare(strict_types = 1);

namespace Orisai\Auth\Authorization;

use Orisai\Auth\Authentication\Data\ExpiredLogin;
use Orisai\Auth\Authentication\DecisionReason;

interface PolicyContext
{

	public function isCurrentUser(): bool;

	public function getAuthorizer(): Authorizer;

	public function setDecisionReason(DecisionReason $reason): void;

	public function getDecisionReason(): ?DecisionReason;

	/**
	 * @return array<ExpiredLogin>
	 */
	public function getExpiredLogins(): array;

}
