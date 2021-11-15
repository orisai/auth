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
	 * @param int|string                      $ownerId
	 * @param array<int|string, array<mixed>> $allowed
	 * @param array<mixed>                    $allPrivileges
	 * @param class-string                    $class
	 */
	protected static function allowInternal(
		string $privilege,
		$ownerId,
		array &$allowed,
		array $allPrivileges,
		bool $throwOnUnknownPrivilege,
		string $class,
		string $function
	): void
	{
		if ($privilege === Authorizer::ALL_PRIVILEGES) {
			$allowed[$ownerId] = $allPrivileges;

			return;
		}

		$privilegeParts = PrivilegeProcessor::parsePrivilege($privilege);
		$privilegeValue = PrivilegeProcessor::getPrivilege($privilege, $privilegeParts, $allPrivileges);

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
	 * @param int|string                      $ownerId
	 * @param array<int|string, array<mixed>> $denied
	 * @param array<mixed>                    $allPrivileges
	 * @param class-string                    $class
	 */
	protected static function denyInternal(
		string $privilege,
		$ownerId,
		array &$denied,
		array $allPrivileges,
		bool $throwOnUnknownPrivilege,
		string $class,
		string $function
	): void
	{
		if ($privilege === Authorizer::ALL_PRIVILEGES) {
			$denied[$ownerId] = [];

			return;
		}

		$privilegeParts = PrivilegeProcessor::parsePrivilege($privilege);
		$privilegeValue = PrivilegeProcessor::getPrivilege($privilege, $privilegeParts, $allPrivileges);

		if ($privilegeValue === null) {
			if ($throwOnUnknownPrivilege) {
				throw UnknownPrivilege::forFunction($privilege, $class, $function);
			}

			return;
		}

		Arrays::removeKey($denied[$ownerId], $privilegeParts);
	}

}
