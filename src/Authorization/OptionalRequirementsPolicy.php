<?php declare(strict_types = 1);

namespace Orisai\Auth\Authorization;

use Orisai\Auth\Authentication\Identity;

/**
 * @phpstan-template R of object
 * @phpstan-extends Policy<R>
 */
interface OptionalRequirementsPolicy extends Policy
{

	public function isAllowed(Identity $identity, ?object $requirements, PolicyContext $context): bool;

}
