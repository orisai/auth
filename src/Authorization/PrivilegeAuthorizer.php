<?php declare(strict_types = 1);

namespace Orisai\Auth\Authorization;

use Orisai\Auth\Authentication\Identity;
use Orisai\Exceptions\Logic\InvalidState;
use function array_key_exists;
use function array_keys;
use function array_merge;
use function array_shift;
use function is_array;

class PrivilegeAuthorizer implements Authorizer
{

	/** @var array<string, null> */
	protected array $roles = [];

	/** @var array<mixed> */
	protected array $privileges = [];

	/** @var array<string, array<mixed>> */
	protected array $rolePrivileges = [];

	/**
	 * @return array<string>
	 */
	public function getRoles(): array
	{
		return array_keys($this->roles);
	}

	public function addRole(string $role): void
	{
		$this->roles[$role] = null;
		$this->rolePrivileges[$role] ??= [];
	}

	private function checkRole(string $role): void
	{
		if (!array_key_exists($role, $this->roles)) {
			$class = static::class;

			throw InvalidState::create()
				->withMessage("Role {$role} does not exist, add it with {$class}->addRole(\$role)");
		}
	}

	/**
	 * @return array<string>
	 */
	public function getPrivileges(): array
	{
		return $this->keysToStrings($this->privileges);
	}

	public function addPrivilege(string $privilege): void
	{
		$privilegeParts = PrivilegeProcessor::parsePrivilege($privilege);

		$privilegesCurrent = &$this->privileges;

		$this->addKeyValue($privilegesCurrent, $privilegeParts, []);
	}

	public function hasPrivilege(string $privilege): bool
	{
		if ($privilege === self::ALL_PRIVILEGES) {
			return true;
		}

		$privilegeValue = $this->getKey($this->privileges, PrivilegeProcessor::parsePrivilege($privilege));

		return $privilegeValue !== null;
	}

	/**
	 * @return array<string>
	 */
	public function getRolePrivileges(string $role): array
	{
		$privileges = $this->rolePrivileges[$role] ?? [];

		return $this->keysToStrings($privileges);
	}

	public function allow(string $role, string $privilege): void
	{
		$this->checkRole($role);

		if ($privilege === self::ALL_PRIVILEGES) {
			$this->rolePrivileges[$role] = $this->privileges;

			return;
		}

		$privilegeParts = PrivilegeProcessor::parsePrivilege($privilege);
		$privilegeValue = $this->getCheckedPrivilege($privilege, $privilegeParts, __FUNCTION__);

		$rolePrivilegesCurrent = &$this->rolePrivileges[$role];

		$this->addKeyValue($rolePrivilegesCurrent, $privilegeParts, $privilegeValue);
	}

	public function deny(string $role, string $privilege): void
	{
		$this->checkRole($role);

		if ($privilege === self::ALL_PRIVILEGES) {
			$this->rolePrivileges[$role] = [];

			return;
		}

		$privilegeParts = PrivilegeProcessor::parsePrivilege($privilege);
		$this->getCheckedPrivilege($privilege, $privilegeParts, __FUNCTION__);

		$this->removeKey($this->rolePrivileges[$role], $privilegeParts);
	}

	public function isAllowed(Identity $identity, string $privilege): bool
	{
		$privilegeParts = PrivilegeProcessor::parsePrivilege($privilege);
		$requiredPrivileges = $this->getCheckedPrivilege($privilege, $privilegeParts, __FUNCTION__);

		foreach ($identity->getRoles() as $role) {
			if (!array_key_exists($role, $this->rolePrivileges)) {
				continue;
			}

			$rolePrivileges = &$this->rolePrivileges[$role];

			if ($this->isAllowedByRole($requiredPrivileges, $rolePrivileges, $privilege, $privilegeParts)) {
				return true;
			}
		}

		return false;
	}

	/**
	 * @param array<mixed> $requiredPrivileges
	 * @param array<mixed> $rolePrivileges
	 * @param array<string> $privilegeParts
	 */
	private function isAllowedByRole(
		array &$requiredPrivileges,
		array $rolePrivileges,
		string $privilege,
		array $privilegeParts
	): bool
	{
		$matchingRolePrivileges = $privilege === self::ALL_PRIVILEGES
			? $rolePrivileges
			: $this->getKey($rolePrivileges, $privilegeParts);

		if ($matchingRolePrivileges === null) {
			return false;
		}

		$this->removeMatchingPartsFromFromFirstArray($requiredPrivileges, $matchingRolePrivileges);

		return $requiredPrivileges === [];
	}

	/**
	 * @param array<string> $privilegeParts
	 * @return array<mixed>
	 */
	private function getCheckedPrivilege(string $privilege, array $privilegeParts, string $function): array
	{
		if ($privilege === self::ALL_PRIVILEGES) {
			return $this->privileges;
		}

		$privilegeValue = $this->getKey($this->privileges, $privilegeParts);

		if ($privilegeValue !== null) {
			return $privilegeValue;
		}

		$class = static::class;

		throw InvalidState::create()
			->withMessage(
				"Privilege {$privilege} is unknown, add with addPrivilege() before calling {$class}->{$function}()",
			);
	}

	/**
	 * @param array<mixed>  $array
	 * @param array<string> $keys
	 * @param array<mixed>  $value
	 */
	private function addKeyValue(array &$array, array $keys, array $value): void
	{
		$currentKey = array_shift($keys);

		if (!array_key_exists($currentKey, $array)) {
			$array[$currentKey] = [];
		}

		if ($keys !== []) {
			$this->addKeyValue($array[$currentKey], $keys, $value);

			return;
		}

		$array[$currentKey] = array_merge($value, $array[$currentKey]);
	}

	/**
	 * @param array<mixed>  $array
	 * @param array<string> $keys
	 * @return array<mixed>|null
	 */
	private function getKey(array &$array, array $keys): ?array
	{
		$currentKey = array_shift($keys);

		if (!array_key_exists($currentKey, $array)) {
			return null;
		}

		if ($keys !== []) {
			return $this->getKey($array[$currentKey], $keys);
		}

		return $array[$currentKey];
	}

	/**
	 * @param array<mixed>  $array
	 * @param array<string> $keys
	 */
	private function removeKey(array &$array, array $keys): void
	{
		$currentKey = array_shift($keys);

		// Key was already removed
		if (!array_key_exists($currentKey, $array)) {
			return;
		}

		// Remove recursively if there are more keys left
		if ($keys !== []) {
			$this->removeKey($array[$currentKey], $keys);

			return;
		}

		unset($array[$currentKey]);
	}

	/**
	 * @param array<mixed> $first
	 * @param array<mixed> $second
	 */
	private function removeMatchingPartsFromFromFirstArray(array &$first, array $second): void
	{
		foreach ($second as $key => $value) {
			if (!array_key_exists($key, $first)) {
				continue;
			}

			if (is_array($value) && $value !== [] && is_array($first[$key]) && $first[$key] !== []) {
				$this->removeMatchingPartsFromFromFirstArray($first[$key], $value);
			}

			if ($value === $first[$key] || ($first[$key] === [] && is_array($value))) {
				unset($first[$key]);
			}
		}
	}

	/**
	 * @param array<mixed> $array
	 * @return array<string>
	 */
	private function keysToStrings(array $array, ?string $baseKey = null): array
	{
		$stringsByKey = [];

		foreach ($array as $key => $value) {
			$compositeKey = $baseKey !== null
				? "$baseKey.$key"
				: $key;

			$stringsByKey[] = is_array($value) && $value !== []
				? $this->keysToStrings($value, $compositeKey)
				: [$compositeKey];
		}

		return array_merge(...$stringsByKey);
	}

}
