<?php declare(strict_types = 1);

namespace Orisai\Auth\Authentication;

use Orisai\Auth\Authentication\Data\Logins;

interface LoginStorage
{

	public function getLogins(string $namespace): Logins;

	public function regenerateSecurityToken(string $namespace): void;

	public function alreadyExists(string $namespace): bool;

}
