<?php declare(strict_types = 1);

namespace Orisai\Auth\Authorization;

use Orisai\Auth\Authentication\Identity;
use Orisai\Auth\Utils\Arrays;
use Orisai\Exceptions\Logic\InvalidArgument;
use Orisai\Exceptions\Logic\InvalidState;
use Orisai\Exceptions\Message;
use ReflectionClass;
use function array_key_exists;
use function array_keys;
use function get_class;
use function is_a;

class PrivilegeAuthorizer implements Authorizer
{

	private PolicyManager $policyManager;

	public bool $throwOnUnknownRolePrivilege = false;

	/** @var array<string, null> */
	protected array $roles = [];

	/** @var array<mixed> */
	protected array $privileges = [];

	/** @var array<string, array<mixed>> */
	protected array $rolePrivileges = [];

	public function __construct(PolicyManager $policyManager)
	{
		$this->policyManager = $policyManager;
	}

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
		return Arrays::keysToStrings($this->privileges);
	}

	public function addPrivilege(string $privilege): void
	{
		$privilegeParts = PrivilegeProcessor::parsePrivilege($privilege);

		$privilegesCurrent = &$this->privileges;

		Arrays::addKeyValue($privilegesCurrent, $privilegeParts, []);
	}

	public function privilegeExists(string $privilege): bool
	{
		if ($privilege === self::ALL_PRIVILEGES) {
			return true;
		}

		$privilegeValue = Arrays::getKey($this->privileges, PrivilegeProcessor::parsePrivilege($privilege));

		return $privilegeValue !== null;
	}

	/**
	 * @return array<string>
	 */
	public function getRolePrivileges(string $role): array
	{
		$privileges = $this->rolePrivileges[$role] ?? [];

		return Arrays::keysToStrings($privileges);
	}

	public function allow(string $role, string $privilege): void
	{
		$this->checkRole($role);

		if ($privilege === self::ALL_PRIVILEGES) {
			$this->rolePrivileges[$role] = $this->privileges;

			return;
		}

		$privilegeParts = PrivilegeProcessor::parsePrivilege($privilege);
		$privilegeValue = $this->getPrivilege($privilege, $privilegeParts);

		if ($privilegeValue === null) {
			if ($this->throwOnUnknownRolePrivilege) {
				$this->unknownPrivilege($privilege, __FUNCTION__);
			}

			return;
		}

		$rolePrivilegesCurrent = &$this->rolePrivileges[$role];

		Arrays::addKeyValue($rolePrivilegesCurrent, $privilegeParts, $privilegeValue);
	}

	public function deny(string $role, string $privilege): void
	{
		$this->checkRole($role);

		if ($privilege === self::ALL_PRIVILEGES) {
			$this->rolePrivileges[$role] = [];

			return;
		}

		$privilegeParts = PrivilegeProcessor::parsePrivilege($privilege);
		$privilegeValue = $this->getPrivilege($privilege, $privilegeParts);

		if ($privilegeValue === null) {
			if ($this->throwOnUnknownRolePrivilege) {
				$this->unknownPrivilege($privilege, __FUNCTION__);
			}

			return;
		}

		Arrays::removeKey($this->rolePrivileges[$role], $privilegeParts);
	}

	public function hasPrivilege(Identity $identity, string $privilege): bool
	{
		return $this->hasPrivilegeInternal($identity, $privilege, __FUNCTION__);
	}

	private function hasPrivilegeInternal(Identity $identity, string $privilege, string $method): bool
	{
		$privilegeParts = PrivilegeProcessor::parsePrivilege($privilege);
		$requiredPrivileges = $this->getPrivilege($privilege, $privilegeParts);

		if ($requiredPrivileges === null) {
			$this->unknownPrivilege($privilege, $method);
		}

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

	public function isAllowed(Identity $identity, string $privilege, ?object $requirements = null): bool
	{
		$policy = $this->policyManager->get($privilege);

		return $policy === null
			? $this->isAllowedByPrivilege($identity, $privilege, $requirements, __FUNCTION__)
			: $this->isAllowedByPolicy($identity, $policy, $requirements, __FUNCTION__);
	}

	private function isAllowedByPrivilege(
		Identity $identity,
		string $privilege,
		?object $requirements,
		string $method
	): bool
	{
		if ($requirements !== null) {
			$class = static::class;
			$requirementsType = get_class($requirements);
			$message = Message::create()
				->withContext("Trying to check privilege $privilege via $class->$method().")
				->withProblem(
					"Passed requirement object (type of $requirementsType) which is not allowed by privilege without policy.",
				)
				->withSolution('Do not pass the requirement object or define policy which can handle it.');

			throw InvalidArgument::create()
				->withMessage($message);
		}

		return $this->hasPrivilegeInternal($identity, $privilege, $method);
	}

	/**
	 * @phpstan-param Policy<object> $policy
	 */
	private function isAllowedByPolicy(Identity $identity, Policy $policy, ?object $requirements, string $method): bool
	{
		$privilege = $policy::getPrivilege();
		if (!$this->privilegeExists($privilege)) {
			$this->unknownPrivilege($privilege, $method);
		}

		$requirementsClass = $policy::getRequirementsClass();
		if ($requirements !== null) {
			if (!is_a($requirements, $requirementsClass, true)) {
				$class = static::class;
				$policyClass = get_class($policy);
				$passedRequirementsClass = get_class($requirements);
				$message = Message::create()
					->withContext("Trying to check privilege $privilege via $class->$method().")
					->withProblem(
						"Passed requirements are of type $passedRequirementsClass, which is not supported by $policyClass.",
					)
					->withSolution(
						"Pass requirements of type $requirementsClass or change policy or its requirements.",
					);

				throw InvalidArgument::create()
					->withMessage($message);
			}
		} elseif ($requirementsClass === NoRequirements::class) {
			$requirements = new NoRequirements();
		} else {
			$methodRef = (new ReflectionClass($policy))->getMethod('isAllowed');

			if (!$methodRef->getParameters()[1]->allowsNull()) {
				$class = static::class;
				$policyClass = get_class($policy);
				$noRequirementsClass = NoRequirements::class;
				$message = Message::create()
					->withContext("Trying to check privilege $privilege via $class->$method().")
					->withProblem("Policy requirements are missing, which is not supported by $policyClass.")
					->withSolution(
						"Pass requirements of type $requirementsClass or mark policy requirements nullable or change them to $noRequirementsClass.",
					);

				throw InvalidArgument::create()
					->withMessage($message);
			}
		}

		return $policy->isAllowed($identity, $requirements, $this);
	}

	/**
	 * @param array<mixed>            $requiredPrivileges
	 * @param array<mixed>            $rolePrivileges
	 * @param non-empty-array<string> $privilegeParts
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
			: Arrays::getKey($rolePrivileges, $privilegeParts);

		if ($matchingRolePrivileges === null) {
			return false;
		}

		Arrays::removeMatchingPartsFromFromFirstArray($requiredPrivileges, $matchingRolePrivileges);

		return $requiredPrivileges === [];
	}

	/**
	 * @param non-empty-array<string> $privilegeParts
	 * @return array<mixed>|null
	 */
	private function getPrivilege(string $privilege, array $privilegeParts): ?array
	{
		if ($privilege === self::ALL_PRIVILEGES) {
			return $this->privileges;
		}

		return Arrays::getKey($this->privileges, $privilegeParts);
	}

	/**
	 * @phpstan-return never-return
	 * @throws InvalidState
	 */
	private function unknownPrivilege(string $privilege, string $method): void
	{
		$class = static::class;

		$message = Message::create()
			->withContext("Trying to call $class->$method().")
			->withProblem("Privilege $privilege is unknown.")
			->withSolution('Add privilege to authorizer first via addPrivilege().');

		throw InvalidState::create()
			->withMessage($message);
	}

}
