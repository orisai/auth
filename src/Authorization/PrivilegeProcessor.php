<?php declare(strict_types = 1);

namespace Orisai\Auth\Authorization;

use Orisai\Exceptions\Logic\InvalidArgument;
use function explode;
use function str_contains;
use function str_ends_with;
use function str_starts_with;

final class PrivilegeProcessor
{

	/**
	 * @return array<string>
	 */
	public static function parsePrivilege(string $privilege): array
	{
		if ($privilege === '') {
			throw InvalidArgument::create()
				->withMessage('Privilege is an empty string, which is not allowed.');
		}

		if (str_starts_with($privilege, '.')) {
			throw InvalidArgument::create()
				->withMessage("Privilege {$privilege} starts with dot `.`, which is not allowed.");
		}

		if (str_ends_with($privilege, '.')) {
			throw InvalidArgument::create()
				->withMessage("Privilege {$privilege} ends with dot `.`, which is not allowed.");
		}

		if ($privilege !== Authorizer::ALL_PRIVILEGES && str_contains($privilege, Authorizer::ALL_PRIVILEGES)) {
			throw InvalidArgument::create()
				->withMessage("Privilege {$privilege} contains `*`, which can be used only standalone.");
		}

		if (str_contains($privilege, '..')) {
			throw InvalidArgument::create()
				->withMessage("Privilege {$privilege} contains multiple adjacent dots, which is not allowed.");
		}

		return explode('.', $privilege);
	}

	/**
	 * @return array<string>
	 */
	public static function getPrivilegeParents(string $privilege, bool $includePowerUser): array
	{
		$all = [];

		if ($includePowerUser) {
			$all[] = Authorizer::ALL_PRIVILEGES;
		}

		$parts = self::parsePrivilege($privilege);
		$current = null;
		foreach ($parts as $part) {
			$current = $current === null ? $part : "{$current}.{$part}";
			$all[] = $current;
		}

		return $all;
	}

}
