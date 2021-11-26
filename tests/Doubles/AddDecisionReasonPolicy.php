<?php declare(strict_types = 1);

namespace Tests\Orisai\Auth\Doubles;

use Orisai\Auth\Authentication\Identity;
use Orisai\Auth\Authorization\DecisionReason;
use Orisai\Auth\Authorization\NoRequirements;
use Orisai\Auth\Authorization\Policy;
use Orisai\Auth\Authorization\PolicyContext;

/**
 * @phpstan-implements Policy<NoRequirements>
 */
final class AddDecisionReasonPolicy implements Policy
{

	public static function getPrivilege(): string
	{
		return 'add-decision-reason';
	}

	public static function getRequirementsClass(): string
	{
		return NoRequirements::class;
	}

	public function isAllowed(Identity $identity, object $requirements, PolicyContext $context): bool
	{
		$context->setDecisionReason(DecisionReason::create('Message'));

		return true;
	}

}
