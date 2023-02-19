<?php declare(strict_types = 1);

namespace Orisai\Auth\Authorization;

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

	private AuthorizationDataCreator $dataCreator;

	private ?AuthorizationData $data = null;

	public function __construct(PolicyManager $policyManager, AuthorizationDataCreator $dataCreator)
	{
		$this->policyManager = $policyManager;
		$this->dataCreator = $dataCreator;
	}

	public function hasPrivilege(Identity $identity, string $privilege): bool
	{
		$hasPrivilege = $this->hasPrivilegeInternal($identity, $privilege, __FUNCTION__);

		if ($this->isRoot($identity)) {
			return true;
		}

		return $hasPrivilege;
	}

	private function hasPrivilegeInternal(Identity $identity, string $privilege, string $function): bool
	{
		$privileges = $this->getData()->getRawPrivileges();

		$privilegeParts = PrivilegeProcessor::parsePrivilege($privilege);
		$requiredPrivileges = Arrays::getKey($privileges, $privilegeParts);

		if ($requiredPrivileges === null) {
			throw UnknownPrivilege::forFunction($privilege, self::class, $function);
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

		$roleAllowedPrivileges = $this->getData()->getRawRoleAllowedPrivileges();
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
		?array &$entries = null,
		?CurrentUserPolicyContextCreator $creator = null
	): bool
	{
		$allowed = $this->isAllowedInternal(
			__FUNCTION__,
			$identity,
			$privilege,
			$requirements,
			$entries,
			$creator,
		);

		if ($identity !== null && $this->isRoot($identity)) {
			return true;
		}

		return $allowed;
	}

	/**
	 * @param array{}|null           $entries
	 * @phpstan-param literal-string $privilege
	 * @param-out list<AccessEntry>  $entries
	 */
	private function isAllowedInternal(
		string $function,
		?Identity $identity,
		string $privilege,
		?object $requirements = null,
		?array &$entries = null,
		?CurrentUserPolicyContextCreator $creator = null
	): bool
	{
		$policy = $this->policyManager->get($privilege);

		if ($policy === null) {
			return $identity !== null
				&& $this->isAllowedByPrivilege($identity, $privilege, $requirements, $function);
		}

		return $this->isAllowedByPolicy(
			$identity,
			$policy,
			$requirements,
			$creator !== null ? $creator->create() : new AnyUserPolicyContext($this),
			$entries,
			$function,
		);
	}

	public function isRoot(Identity $identity): bool
	{
		$identityAuthData = $identity->getAuthorizationData();
		if ($identityAuthData !== null && $identityAuthData->isRoot()) {
			return true;
		}

		$rootRoles = $this->getData()->getRawRootRoles();
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
				->withContext("Checking privilege $privilege via $class->$function().")
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
	 * @param array{}|null           $entries
	 * @phpstan-param Policy<object> $policy
	 */
	private function isAllowedByPolicy(
		?Identity $identity,
		Policy $policy,
		?object $requirements,
		PolicyContext $context,
		?array &$entries,
		string $function
	): bool
	{
		$privilege = $policy::getPrivilege();
		if (!$this->getData()->privilegeExists($privilege)) {
			throw UnknownPrivilege::forFunction($privilege, self::class, $function);
		}

		$requirementsClass = $policy::getRequirementsClass();
		if ($requirements !== null) {
			if (!is_a($requirements, $requirementsClass, true)) {
				$class = self::class;
				$policyClass = get_class($policy);
				$passedRequirementsClass = get_class($requirements);
				$message = Message::create()
					->withContext("Checking privilege $privilege via $class->$function().")
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
				->withContext("Checking privilege $privilege via $class->$function().")
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

		$isAllowed = true;
		$entries = [];
		foreach ($policy->isAllowed($identity, $requirements, $context) as $entry) {
			$entries[] = $entry;

			// If any entry is not allowed, policy forbids access
			if ($isAllowed && $entry->getResult() !== AccessEntryResult::allowed()) {
				$isAllowed = false;
			}
		}

		if ($entries === []) {
			$policyClass = get_class($policy);
			$entryClass = AccessEntry::class;
			$message = Message::create()
				->withContext("Checking policy '$policyClass'.")
				->withProblem("Policy yielded no '$entryClass'.")
				->withSolution('Yield at least one entry.');

			throw InvalidArgument::create()->withMessage($message);
		}

		return $isAllowed;
	}

	public function getData(): AuthorizationData
	{
		return $this->data
			?? ($this->data = $this->dataCreator->create());
	}

}
