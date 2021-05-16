<?php declare(strict_types = 1);

namespace Orisai\Auth\Authentication;

use Brick\DateTime\Clock;
use Brick\DateTime\Clock\SystemClock;
use Brick\DateTime\Duration;
use Brick\DateTime\Instant;
use Orisai\Auth\Authentication\Data\CurrentExpiration;
use Orisai\Auth\Authentication\Data\CurrentLogin;
use Orisai\Auth\Authentication\Data\ExpiredLogin;
use Orisai\Auth\Authentication\Data\Logins;
use Orisai\Auth\Authentication\Exception\NotLoggedIn;
use Orisai\Auth\Authorization\Authorizer;
use Orisai\Auth\Authorization\NoRequirements;
use Orisai\Auth\Authorization\Policy;
use Orisai\Auth\Authorization\PolicyManager;
use Orisai\Exceptions\Logic\InvalidArgument;
use Orisai\Exceptions\Logic\InvalidState;
use Orisai\Exceptions\Message;
use ReflectionClass;
use function get_class;
use function is_a;

/**
 * @phpstan-template I of Identity
 * @phpstan-template-covariant F of Firewall
 * @phpstan-template-covariant P of Policy
 * @phpstan-implements Firewall<I, F>
 */
abstract class BaseFirewall implements Firewall
{

	private LoginStorage $storage;

	/** @phpstan-var IdentityRenewer<I> */
	private IdentityRenewer $renewer;

	private Authorizer $authorizer;

	/** @phpstan-var PolicyManager<P> */
	private PolicyManager $policyManager;

	private Clock $clock;

	protected ?Logins $logins = null;

	private int $expiredIdentitiesLimit = self::EXPIRED_IDENTITIES_DEFAULT_LIMIT;

	/**
	 * @phpstan-param IdentityRenewer<I> $renewer
	 * @phpstan-param PolicyManager<P> $policyManager
	 */
	public function __construct(
		LoginStorage $storage,
		IdentityRenewer $renewer,
		Authorizer $authorizer,
		PolicyManager $policyManager,
		?Clock $clock = null
	)
	{
		$this->storage = $storage;
		$this->renewer = $renewer;
		$this->authorizer = $authorizer;
		$this->policyManager = $policyManager;
		$this->clock = $clock ?? new SystemClock();
	}

	abstract protected function getNamespace(): string;

	public function isLoggedIn(): bool
	{
		return $this->fetchIdentity() !== null;
	}

	public function login(Identity $identity): void
	{
		$logins = $this->getLogins();

		$previousLogin = $logins->getCurrentLogin();
		if ($previousLogin !== null && $previousLogin->getIdentity()->getId() !== $identity->getId()) {
			$this->addExpiredLogin(new ExpiredLogin($previousLogin, $this::REASON_MANUAL));
		}

		$logins->setCurrentLogin(new CurrentLogin($identity, $this->clock->getTime()));

		$this->storage->regenerateSecurityToken($this->getNamespace());
	}

	/**
	 * @throws NotLoggedIn
	 */
	public function renewIdentity(Identity $identity): void
	{
		$login = $this->getLogins()->getCurrentLogin();

		if ($login === null) {
			throw NotLoggedIn::create(static::class, __FUNCTION__);
		}

		$login->setIdentity($identity);
	}

	public function logout(): void
	{
		if (!$this->doesStorageAlreadyExist()) {
			return;
		}

		$this->unauthenticate(self::REASON_MANUAL, $this->getLogins());
	}

	/**
	 * @phpstan-param self::REASON_* $reason
	 */
	private function unauthenticate(int $reason, Logins $logins): void
	{
		$login = $logins->getCurrentLogin();

		if ($login === null) {
			return;
		}

		$logins->removeCurrentLogin();
		$this->addExpiredLogin(new ExpiredLogin($login, $reason));

		$this->storage->regenerateSecurityToken($this->getNamespace());
	}

	/**
	 * @throws NotLoggedIn
	 */
	public function getIdentity(): Identity
	{
		$identity = $this->fetchIdentity();

		if ($identity === null) {
			throw NotLoggedIn::create(static::class, __FUNCTION__);
		}

		return $identity;
	}

	protected function fetchCurrentLogin(): ?CurrentLogin
	{
		if (!$this->doesStorageAlreadyExist()) {
			return null;
		}

		return $this->getLogins()->getCurrentLogin();
	}

	protected function fetchIdentity(): ?Identity
	{
		$login = $this->fetchCurrentLogin();

		return $login === null ? null : $login->getIdentity();
	}

	public function getAuthenticationTime(): Instant
	{
		$login = $this->fetchCurrentLogin();

		if ($login === null) {
			throw NotLoggedIn::create(static::class, __FUNCTION__);
		}

		return $login->getAuthenticationTime();
	}

	public function hasRole(string $role): bool
	{
		$identity = $this->fetchIdentity();

		if ($identity === null) {
			return false;
		}

		return $identity->hasRole($role);
	}

	public function isAllowed(string $privilege, ?object $requirements = null): bool
	{
		$policy = $this->policyManager->get($privilege);

		return $policy === null
			? $this->isAllowedByPrivilege($privilege, $requirements, __FUNCTION__)
			: $this->isAllowedByPolicy($policy, $requirements, __FUNCTION__);
	}

	public function hasPrivilege(string $privilege): bool
	{
		$identity = $this->fetchIdentity();

		if ($identity === null) {
			return false;
		}

		return $this->authorizer->isAllowed($identity, $privilege);
	}

	private function isAllowedByPrivilege(string $privilege, ?object $requirements, string $method): bool
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

		return $this->hasPrivilege($privilege);
	}

	private function isAllowedByPolicy(Policy $policy, ?object $requirements, string $method): bool
	{
		$privilege = $policy::getPrivilege();
		$class = static::class;
		if (!$this->authorizer->hasPrivilege($privilege)) {
			$authorizerClass = get_class($this->authorizer);
			$message = Message::create()
				->withContext("Trying to check privilege $privilege via $class->$method().")
				->withProblem("Privilege $privilege is not known by underlying authorizer (type of $authorizerClass).")
				->withSolution('Add privilege to authorizer first.');

			throw InvalidState::create()
				->withMessage($message);
		}

		$requirementsClass = $policy::getRequirementsClass();
		if ($requirements !== null) {
			if (!is_a($requirements, $requirementsClass, true)) {
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

		if (!$this->isLoggedIn()) {
			return false;
		}

		return $policy->isAllowed($this, $requirements);
	}

	/**
	 * @throws NotLoggedIn
	 */
	public function setExpiration(Instant $time): void
	{
		$login = $this->getLogins()->getCurrentLogin();

		if ($login === null) {
			throw NotLoggedIn::create(static::class, __FUNCTION__);
		}

		$delta = $time->getEpochSecond() - $this->clock->getTime()->getEpochSecond();
		$login->setExpiration(new CurrentExpiration($time, Duration::ofSeconds($delta)));

		if ($delta <= 0) {
			$message = Message::create()
				->withContext('Trying to set login expiration time.')
				->withProblem('Expiration time is lower than current time.')
				->withSolution('Choose expiration time which is in future.');

			throw InvalidArgument::create()
				->withMessage($message);
		}
	}

	public function removeExpiration(): void
	{
		$login = $this->fetchCurrentLogin();

		if ($login === null) {
			return;
		}

		$login->removeExpiration();
	}

	private function checkInactivity(Logins $logins): void
	{
		$login = $logins->getCurrentLogin();

		if ($login === null) {
			return;
		}

		$expiration = $login->getExpiration();

		if ($expiration === null) {
			return;
		}

		$now = $this->clock->getTime();

		if ($expiration->getTime()->isBefore($now)) {
			$this->unauthenticate(self::REASON_INACTIVITY, $logins);
		} else {
			$expiration->setTime($now->plusSeconds($expiration->getDelta()->toSeconds()));
		}
	}

	private function checkIdentity(Logins $logins): void
	{
		$login = $logins->getCurrentLogin();

		if ($login === null) {
			return;
		}

		$identity = $this->renewer->renewIdentity($login->getIdentity());

		if ($identity === null) {
			$this->unauthenticate(self::REASON_INVALID_IDENTITY, $logins);
		} else {
			$login->setIdentity($identity);
		}
	}

	/**
	 * @return array<ExpiredLogin>
	 */
	public function getExpiredLogins(): array
	{
		if (!$this->doesStorageAlreadyExist()) {
			return [];
		}

		return $this->getLogins()->getExpiredLogins();
	}

	public function getLastExpiredLogin(): ?ExpiredLogin
	{
		if (!$this->doesStorageAlreadyExist()) {
			return null;
		}

		return $this->getLogins()->getLastExpiredLogin();
	}

	public function removeExpiredLogins(): void
	{
		if (!$this->doesStorageAlreadyExist()) {
			return;
		}

		$this->getLogins()->removeExpiredLogins();
	}

	/**
	 * @param int|string $id
	 */
	public function removeExpiredLogin($id): void
	{
		if (!$this->doesStorageAlreadyExist()) {
			return;
		}

		$this->getLogins()->removeExpiredLogin($id);
	}

	public function setExpiredIdentitiesLimit(int $count): void
	{
		$this->expiredIdentitiesLimit = $count;

		if ($this->doesStorageAlreadyExist()) {
			$this->getLogins()->removeOldestExpiredLoginsAboveLimit($count);
		}
	}

	private function addExpiredLogin(ExpiredLogin $login): void
	{
		$logins = $this->getLogins();
		$logins->addExpiredLogin($login);
		$logins->removeOldestExpiredLoginsAboveLimit($this->expiredIdentitiesLimit);
	}

	protected function getLogins(): Logins
	{
		if ($this->logins !== null) {
			return $this->logins;
		}

		$logins = $this->storage->getLogins($this->getNamespace());

		$this->upToDateChecks($logins);

		return $this->logins = $logins;
	}

	protected function doesStorageAlreadyExist(): bool
	{
		return $this->storage->alreadyExists($this->getNamespace());
	}

	private function upToDateChecks(Logins $logins): void
	{
		$this->checkInactivity($logins);
		$this->checkIdentity($logins);
	}

}
