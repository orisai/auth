<?php declare(strict_types = 1);

namespace Orisai\Auth\Authorization;

use Orisai\Auth\Authentication\DecisionReason;
use Orisai\Auth\Authentication\Identity;
use Orisai\Auth\Authorization\Exception\UnknownPrivilege;
use Orisai\Auth\Utils\Arrays;
use Orisai\Exceptions\Logic\InvalidArgument;
use Orisai\Exceptions\Message;
use function array_key_exists;
use function get_class;
use function is_a;

final class PrivilegeAuthorizer implements Authorizer
{

	private PolicyManager $policyManager;

	private AuthorizationData $data;

	public function __construct(PolicyManager $policyManager, AuthorizationData $data)
	{
		$this->policyManager = $policyManager;
		$this->data = $data;
	}

	public function hasPrivilege(Identity $identity, string $privilege): bool
	{
		return $this->hasPrivilegeInternal($identity, $privilege, __FUNCTION__);
	}

	private function hasPrivilegeInternal(Identity $identity, string $privilege, string $function): bool
	{
		$privileges = $this->data->getRawPrivileges();

		$privilegeParts = PrivilegeProcessor::parsePrivilege($privilege);
		$requiredPrivileges = Arrays::getKey($privileges, $privilegeParts);

		if ($requiredPrivileges === null) {
			throw UnknownPrivilege::forFunction($privilege, self::class, $function);
		}

		if ($this->isRoot($identity)) {
			return true;
		}

		$identityAuthData = $identity->getAuthorizationData();
		if ($identityAuthData !== null) {
			$allowedPrivileges = $identityAuthData->getRawAllowedPrivileges();

			if ($this->hasPrivilegeSubtractSubset(
				$requiredPrivileges,
				$allowedPrivileges,
				$privilegeParts,
			)) {
				return true;
			}
		}

		$roleAllowedPrivileges = $this->data->getRawRoleAllowedPrivileges();
		foreach ($identity->getRoles() as $role) {
			if (!array_key_exists($role, $roleAllowedPrivileges)) {
				continue;
			}

			$allowedPrivileges = &$roleAllowedPrivileges[$role];

			if ($this->hasPrivilegeSubtractSubset(
				$requiredPrivileges,
				$allowedPrivileges,
				$privilegeParts,
			)) {
				return true;
			}
		}

		return false;
	}

	/**
	 * @param array<mixed>            $requiredPrivileges
	 * @param array<mixed>            $allowedPrivileges
	 * @param non-empty-array<string> $privilegeParts
	 */
	private function hasPrivilegeSubtractSubset(
		array &$requiredPrivileges,
		array $allowedPrivileges,
		array $privilegeParts
	): bool
	{
		$matchingAllowedPrivileges = Arrays::getKey($allowedPrivileges, $privilegeParts);

		if ($matchingAllowedPrivileges === null) {
			return false;
		}

		Arrays::removeMatchingPartsFromFromFirstArray($requiredPrivileges, $matchingAllowedPrivileges);

		return $requiredPrivileges === [];
	}

	public function isAllowed(
		?Identity $identity,
		string $privilege,
		?object $requirements = null,
		?DecisionReason &$reason = null,
		?CurrentUserPolicyContextCreator $creator = null
	): bool
	{
		$policy = $this->policyManager->get($privilege);

		if ($policy === null) {
			return $identity !== null
				&& $this->isAllowedByPrivilege($identity, $privilege, $requirements, __FUNCTION__);
		}

		return $this->isAllowedByPolicy(
			$identity,
			$policy,
			$requirements,
			$creator !== null ? $creator->create() : new AnyUserPolicyContext($this),
			$reason,
			__FUNCTION__,
		);
	}

	public function isRoot(Identity $identity): bool
	{
		$identityAuthData = $identity->getAuthorizationData();
		if ($identityAuthData !== null && $identityAuthData->isRoot()) {
			return true;
		}

		$rootRoles = $this->data->getRawRootRoles();
		foreach ($identity->getRoles() as $role) {
			if (array_key_exists($role, $rootRoles)) {
				return true;
			}
		}

		return false;
	}

	private function isAllowedByPrivilege(
		Identity $identity,
		string $privilege,
		?object $requirements,
		string $function
	): bool
	{
		if ($requirements !== null) {
			$class = self::class;
			$requirementsType = get_class($requirements);
			$message = Message::create()
				->withContext("Trying to check privilege $privilege via $class->$function().")
				->withProblem(
					"Passed requirement object (type of $requirementsType) which is not allowed by privilege without policy.",
				)
				->withSolution('Do not pass the requirement object or define policy which can handle it.');

			throw InvalidArgument::create()
				->withMessage($message);
		}

		return $this->hasPrivilegeInternal($identity, $privilege, $function);
	}

	/**
	 * @phpstan-param Policy<object> $policy
	 */
	private function isAllowedByPolicy(
		?Identity $identity,
		Policy $policy,
		?object $requirements,
		PolicyContext $context,
		?DecisionReason &$reason,
		string $function
	): bool
	{
		$privilege = $policy::getPrivilege();
		if (!$this->data->privilegeExists($privilege)) {
			throw UnknownPrivilege::forFunction($privilege, self::class, $function);
		}

		$requirementsClass = $policy::getRequirementsClass();
		if ($requirements !== null) {
			if (!is_a($requirements, $requirementsClass, true)) {
				$class = self::class;
				$policyClass = get_class($policy);
				$passedRequirementsClass = get_class($requirements);
				$message = Message::create()
					->withContext("Trying to check privilege $privilege via $class->$function().")
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
		} elseif (!$policy instanceof OptionalRequirementsPolicy) {
			$class = self::class;
			$policyClass = get_class($policy);
			$noRequirementsClass = NoRequirements::class;
			$optionalRequirementsClass = OptionalRequirementsPolicy::class;
			$message = Message::create()
				->withContext("Trying to check privilege $privilege via $class->$function().")
				->withProblem("Policy requirements are missing, which is not supported by $policyClass.")
				->withSolution(
					"Pass requirements of type $requirementsClass or implement $optionalRequirementsClass or change them to $noRequirementsClass.",
				);

			throw InvalidArgument::create()
				->withMessage($message);
		}

		if ($identity === null && !$policy instanceof OptionalIdentityPolicy) {
			return false;
		}

		if ($identity !== null && $this->isRoot($identity)) {
			return true;
		}

		$isAllowed = $policy->isAllowed($identity, $requirements, $context);

		$reason = $context->getDecisionReason();

		return $isAllowed;
	}

}
