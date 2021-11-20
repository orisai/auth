<?php declare(strict_types = 1);

namespace Orisai\Auth\Authorization;

use Orisai\Auth\Authentication\Identity;
use Orisai\Auth\Authorization\Exception\UnknownPrivilege;
use Orisai\Auth\Utils\Arrays;
use Orisai\Exceptions\Logic\InvalidArgument;
use Orisai\Exceptions\Message;
use ReflectionClass;
use function array_key_exists;
use function get_class;
use function is_a;

final class PrivilegeAuthorizer implements Authorizer
{

	private PolicyManager $policyManager;

	protected AuthorizationData $data;

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
		$requiredPrivileges = PrivilegeProcessor::getAnyRawPrivilege($privilegeParts, $privileges);

		if ($requiredPrivileges === null) {
			throw UnknownPrivilege::forFunction($privilege, self::class, $function);
		}

		$identityAuthData = $identity->getAuthData();
		if ($identityAuthData !== null) {
			$allowedPrivileges = $identityAuthData->getRawAllowedPrivileges();

			if ($this->isAllowedMatchSubset($requiredPrivileges, $allowedPrivileges, $privilege, $privilegeParts)) {
				return true;
			}
		}

		$roleAllowedPrivileges = $this->data->getRawRoleAllowedPrivileges();
		foreach ($identity->getRoles() as $role) {
			if (!array_key_exists($role, $roleAllowedPrivileges)) {
				continue;
			}

			$allowedPrivileges = &$roleAllowedPrivileges[$role];

			if ($this->isAllowedMatchSubset($requiredPrivileges, $allowedPrivileges, $privilege, $privilegeParts)) {
				return true;
			}
		}

		return false;
	}

	public function isAllowed(
		?Identity $identity,
		string $privilege,
		?object $requirements = null,
		?CurrentUserPolicyContext $context = null
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
			$context ?? new AnyUserPolicyContext($this),
			__FUNCTION__,
		);
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
	 * @param CurrentUserPolicyContext|AnyUserPolicyContext $context
	 * @phpstan-param Policy<object> $policy
	 */
	private function isAllowedByPolicy(
		?Identity $identity,
		Policy $policy,
		?object $requirements,
		PolicyContext $context,
		string $function
	): bool
	{
		$privilege = $policy::getPrivilege();
		if (!$this->data->privilegeExists($privilege)) {
			throw UnknownPrivilege::forFunction($privilege, self::class, $function);
		}

		if ($identity === null && !$policy instanceof OptionalIdentityPolicy) {
			return false;
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
		} else {
			$methodRef = (new ReflectionClass($policy))->getMethod('isAllowed');

			if (!$methodRef->getParameters()[1]->allowsNull()) {
				$class = self::class;
				$policyClass = get_class($policy);
				$noRequirementsClass = NoRequirements::class;
				$message = Message::create()
					->withContext("Trying to check privilege $privilege via $class->$function().")
					->withProblem("Policy requirements are missing, which is not supported by $policyClass.")
					->withSolution(
						"Pass requirements of type $requirementsClass or mark policy requirements nullable or change them to $noRequirementsClass.",
					);

				throw InvalidArgument::create()
					->withMessage($message);
			}
		}

		return $policy->isAllowed($identity, $requirements, $context);
	}

	/**
	 * @param array<mixed>            $requiredPrivileges
	 * @param array<mixed>            $allowedPrivileges
	 * @param non-empty-array<string> $privilegeParts
	 */
	private function isAllowedMatchSubset(
		array &$requiredPrivileges,
		array $allowedPrivileges,
		string $privilege,
		array $privilegeParts
	): bool
	{
		$matchingAllowedPrivileges = $privilege === self::ALL_PRIVILEGES
			? $allowedPrivileges
			: Arrays::getKey($allowedPrivileges, $privilegeParts);

		if ($matchingAllowedPrivileges === null) {
			return false;
		}

		Arrays::removeMatchingPartsFromFromFirstArray($requiredPrivileges, $matchingAllowedPrivileges);

		return $requiredPrivileges === [];
	}

}
