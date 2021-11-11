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

	protected AuthorizationDataBuilder $builder;

	public function __construct(PolicyManager $policyManager)
	{
		$this->policyManager = $policyManager;
		$this->builder = new AuthorizationDataBuilder($this);
	}

	/**
	 * @return array<string>
	 */
	public function getRoles(): array
	{
		$roles = $this->builder->build()->getRoles();

		return array_keys($roles);
	}

	public function addRole(string $role): void
	{
		$this->builder->addRole($role);
	}

	/**
	 * @return array<string>
	 */
	public function getPrivileges(): array
	{
		$privileges = $this->builder->build()->getPrivileges();

		return Arrays::keysToStrings($privileges);
	}

	public function addPrivilege(string $privilege): void
	{
		$this->builder->addPrivilege($privilege);
	}

	public function privilegeExists(string $privilege): bool
	{
		if ($privilege === self::ALL_PRIVILEGES) {
			return true;
		}

		$privileges = $this->builder->build()->getPrivileges();
		$privilegeValue = Arrays::getKey($privileges, PrivilegeProcessor::parsePrivilege($privilege));

		return $privilegeValue !== null;
	}

	/**
	 * @return array<string>
	 */
	public function getAllowedPrivilegesForRole(string $role): array
	{
		$roleAllowedPrivileges = $this->builder->build()->getRoleAllowedPrivileges();

		$privileges = $roleAllowedPrivileges[$role] ?? [];

		return Arrays::keysToStrings($privileges);
	}

	public function allow(string $role, string $privilege): void
	{
		$this->builder->allow($role, $privilege);
	}

	public function deny(string $role, string $privilege): void
	{
		$this->builder->deny($role, $privilege);
	}

	public function hasPrivilege(Identity $identity, string $privilege): bool
	{
		return $this->hasPrivilegeInternal($identity, $privilege, __FUNCTION__);
	}

	private function hasPrivilegeInternal(Identity $identity, string $privilege, string $method): bool
	{
		$privileges = $this->builder->build()->getPrivileges();

		$privilegeParts = PrivilegeProcessor::parsePrivilege($privilege);
		$requiredPrivileges = PrivilegeProcessor::getPrivilege($privilege, $privilegeParts, $privileges);

		if ($requiredPrivileges === null) {
			$this->unknownPrivilege($privilege, $method);
		}

		foreach ($identity->getRoles() as $role) {
			$roleAllowedPrivileges = $this->builder->build()->getRoleAllowedPrivileges();
			if (!array_key_exists($role, $roleAllowedPrivileges)) {
				continue;
			}

			$rolePrivileges = &$roleAllowedPrivileges[$role];

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
	 * @phpstan-return never-return
	 * @throws InvalidState
	 *
	 * @internal
	 */
	public function unknownPrivilege(string $privilege, string $method): void
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
