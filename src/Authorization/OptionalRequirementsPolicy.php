<?php declare(strict_types = 1);

namespace Orisai\Auth\Authorization;

use Generator;
use Orisai\Auth\Authentication\Identity;

/**
 * @template R of object
 * @extends Policy<R>
 */
interface OptionalRequirementsPolicy extends Policy
{

	public function isAllowed(Identity $identity, ?object $requirements, PolicyContext $context): Generator;

}
