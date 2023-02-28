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
	 * @return non-empty-list<string>
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

		if (str_contains($privilege, '..')) {
			throw InvalidArgument::create()
				->withMessage("Privilege {$privilege} contains multiple adjacent dots, which is not allowed.");
		}

		return explode('.', $privilege);
	}

	/**
	 * @return non-empty-list<string>
	 */
	public static function getPrivilegeParents(string $privilege): array
	{
		$all = [];
		$parts = self::parsePrivilege($privilege);
		$current = null;
		foreach ($parts as $part) {
			$current = $current === null ? $part : "{$current}.{$part}";
			$all[] = $current;
		}

		return $all;
	}

}
