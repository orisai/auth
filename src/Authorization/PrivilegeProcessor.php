<?php declare(strict_types = 1);

namespace Orisai\Auth\Authorization;

use Orisai\Auth\Authorization\Exception\UnknownPrivilege;
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

	/**
	 * @param array<mixed>            $privileges
	 * @param non-empty-array<string> $privilegeParts
	 * @return array<mixed>|null
	 */
	public static function getPrivilege(string $privilege, array $privilegeParts, array $privileges): ?array
	{
		if ($privilege === Authorizer::ALL_PRIVILEGES) {
			return $privileges;
		}

		return Arrays::getKey($privileges, $privilegeParts);
	}

	/**
	 * @param int|string                      $allowedKey
	 * @param array<int|string, array<mixed>> $allowed
	 * @param array<mixed>                    $allPrivileges
	 * @param class-string                    $class
	 */
	public static function allow(
		string $privilege,
		$allowedKey,
		array &$allowed,
		array $allPrivileges,
		bool $throwOnUnknownRolePrivilege,
		string $class,
		string $function
	): void
	{
		if ($privilege === Authorizer::ALL_PRIVILEGES) {
			$allowed[$allowedKey] = $allPrivileges;

			return;
		}

		$privilegeParts = self::parsePrivilege($privilege);
		$privilegeValue = self::getPrivilege($privilege, $privilegeParts, $allPrivileges);

		if ($privilegeValue === null) {
			if ($throwOnUnknownRolePrivilege) {
				throw UnknownPrivilege::forFunction($privilege, $class, $function);
			}

			return;
		}

		$rolePrivilegesCurrent = &$allowed[$allowedKey];

		Arrays::addKeyValue($rolePrivilegesCurrent, $privilegeParts, $privilegeValue);
	}

	/**
	 * @param int|string                      $deniedKey
	 * @param array<int|string, array<mixed>> $denied
	 * @param array<mixed>                    $allPrivileges
	 * @param class-string                    $class
	 */
	public static function deny(
		string $privilege,
		$deniedKey,
		array &$denied,
		array $allPrivileges,
		bool $throwOnUnknownRolePrivilege,
		string $class,
		string $function
	): void
	{
		if ($privilege === Authorizer::ALL_PRIVILEGES) {
			$denied[$deniedKey] = [];

			return;
		}

		$privilegeParts = self::parsePrivilege($privilege);
		$privilegeValue = self::getPrivilege($privilege, $privilegeParts, $allPrivileges);

		if ($privilegeValue === null) {
			if ($throwOnUnknownRolePrivilege) {
				throw UnknownPrivilege::forFunction($privilege, $class, $function);
			}

			return;
		}

		Arrays::removeKey($denied[$deniedKey], $privilegeParts);
	}

}
