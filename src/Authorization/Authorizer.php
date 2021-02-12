<?php declare(strict_types = 1);

namespace Orisai\Auth\Authorization;

use Orisai\Auth\Authentication\Identity;

interface Authorizer
{

	public const ALL_PRIVILEGES = '*';

	public function hasPrivilege(string $privilege): bool;

	public function isAllowed(Identity $identity, string $privilege): bool;

}
