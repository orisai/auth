<?php declare(strict_types = 1);

namespace Orisai\Auth\Authorization;

use Generator;
use Orisai\Auth\Authentication\Identity;

/**
 * @phpstan-template R of object
 * @phpstan-extends Policy<R>
 */
interface OptionalIdentityPolicy extends Policy
{

	public function isAllowed(?Identity $identity, object $requirements, PolicyContext $context): Generator;

}
