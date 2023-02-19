<?php declare(strict_types = 1);

namespace Orisai\Auth\Authorization;

/**
 * @readonly
 */
final class AnyUserPolicyContext extends BaseUserPolicyContext
{

	public function isCurrentUser(): bool
	{
		return false;
	}

	public function getExpiredLogins(): array
	{
		return [];
	}

}
