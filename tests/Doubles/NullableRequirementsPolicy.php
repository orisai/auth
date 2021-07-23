<?php declare(strict_types = 1);

namespace Tests\Orisai\Auth\Doubles;

use Orisai\Auth\Authentication\Identity;
use Orisai\Auth\Authorization\Authorizer;
use Orisai\Auth\Authorization\Policy;

/**
 * @phpstan-implements Policy<Article>
 */
final class NullableRequirementsPolicy implements Policy
{

	public static function getPrivilege(): string
	{
		return 'nullable-requirements';
	}

	public static function getRequirementsClass(): string
	{
		return Article::class;
	}

	public function isAllowed(Identity $identity, ?object $requirements, Authorizer $authorizer): bool
	{
		return false;
	}

}
