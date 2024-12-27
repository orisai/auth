<?php declare(strict_types = 1);

namespace Orisai\Auth\Authorization;

use Orisai\Auth\Authorization\Exception\UnknownPrivilege;
use Orisai\Auth\Utils\Arrays;
use function array_key_exists;

/**
 * @internal
 */
abstract class BaseAuthorizationDataBuilder
{

	/**
	 * @template T_OWNER of int|string
	 * @param T_OWNER $ownerId
	 * @param array<T_OWNER, array<mixed>> $allowed
	 * @param array<mixed> $allPrivileges
	 * @param class-string $class
	 */
	protected static function addPrivilegeToList(
		string $privilege,
		$ownerId,
		array &$allowed,
		array $allPrivileges,
		bool $throwOnUnknownPrivilege,
		string $class,
		string $function
	): void
	{
		$privilegeParts = PrivilegeProcessor::parsePrivilege($privilege);
		$privilegeValue = Arrays::getKey($allPrivileges, $privilegeParts);

		if ($privilegeValue === null) {
			if ($throwOnUnknownPrivilege) {
				throw UnknownPrivilege::forFunction($privilege, $class, $function);
			}

			return;
		}

		if (!array_key_exists($ownerId, $allowed)) {
			$allowed[$ownerId] = [];
		}

		$rolePrivilegesCurrent = &$allowed[$ownerId];

		Arrays::addKeyValue($rolePrivilegesCurrent, $privilegeParts, $privilegeValue);
	}

	/**
	 * @template T_OWNER of int|string
	 * @param T_OWNER $ownerId
	 * @param array<T_OWNER, array<mixed>> $denied
	 * @param array<mixed> $allPrivileges
	 * @param class-string $class
	 */
	protected static function removePrivilegeFromList(
		string $privilege,
		$ownerId,
		array &$denied,
		array $allPrivileges,
		bool $throwOnUnknownPrivilege,
		string $class,
		string $function
	): void
	{
		$privilegeParts = PrivilegeProcessor::parsePrivilege($privilege);
		$privilegeValue = Arrays::getKey($allPrivileges, $privilegeParts);

		if ($privilegeValue === null) {
			if ($throwOnUnknownPrivilege) {
				throw UnknownPrivilege::forFunction($privilege, $class, $function);
			}

			return;
		}

		Arrays::removeKey($denied[$ownerId], $privilegeParts);
	}

}
