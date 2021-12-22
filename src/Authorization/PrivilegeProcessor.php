<?php declare(strict_types = 1);

namespace Orisai\Auth\Authorization;

use Orisai\Auth\Utils\Arrays;
use Orisai\Exceptions\Logic\InvalidArgument;
use function explode;
use function str_contains;
use function str_ends_with;
use function str_starts_with;

final class PrivilegeProcessor
{

	/**
	 * @return non-empty-array<string>
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

		if ($privilege !== Authorizer::ROOT_PRIVILEGE && str_contains($privilege, Authorizer::ROOT_PRIVILEGE)) {
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
			$all[] = Authorizer::ROOT_PRIVILEGE;
		}

		$parts = self::parsePrivilege($privilege);
		$current = null;
		foreach ($parts as $part) {
			$current = $current === null ? $part : "{$current}.{$part}";
			$all[] = $current;
		}

		return $all;
	}

	/**
	 * @param array<mixed>            $rawPrivileges
	 * @param non-empty-array<string> $privilegeParts
	 * @return array<mixed>|null
	 */
	public static function getAnyRawPrivilege(array $privilegeParts, array $rawPrivileges): ?array
	{
		if ($privilegeParts === [Authorizer::ROOT_PRIVILEGE]) {
			return $rawPrivileges;
		}

		return Arrays::getKey($rawPrivileges, $privilegeParts);
	}

}
