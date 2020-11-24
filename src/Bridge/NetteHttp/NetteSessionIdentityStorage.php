<?php declare(strict_types = 1);

namespace Orisai\Auth\Bridge\NetteHttp;

use __PHP_Incomplete_Class;
use DateTimeInterface;
use Nette\Http\Session;
use Nette\Http\SessionSection;
use Orisai\Auth\Authentication\Identity;
use Orisai\Auth\Authentication\IdentityRenewer;
use Orisai\Auth\Authentication\IdentityStorage;
use Orisai\Exceptions\Logic\InvalidArgument;
use Orisai\Exceptions\Logic\InvalidState;
use Orisai\Exceptions\Message;
use function ini_get;
use function sprintf;
use function time;

final class NetteSessionIdentityStorage implements IdentityStorage
{

	private const SESSION_PREFIX = 'orisai.auth';

	private string $namespace;

	private Session $session;
	private ?SessionSection $sessionSection = null;

	private ?IdentityRenewer $identityRenewer;

	public function __construct(string $namespace, Session $session, ?IdentityRenewer $identityRenewer = null)
	{
		$this->namespace = $namespace;
		$this->session = $session;
		$this->identityRenewer = $identityRenewer;
	}

	public function getIdentity(): ?Identity
	{
		if (!$this->session->exists()) {
			return null;
		}

		return $this->getSessionSection()->identity;
	}

	public function login(Identity $identity): void
	{
		$section = $this->getSessionSection();

		$section->identity = $identity;
		$section->authenticated = true;
		$section->logoutReason = null;
		$section->authenticationTime = time();

		$this->session->regenerateId();
	}

	/**
	 * @phpstan-param self::REASON_* $reason
	 */
	public function logout(int $reason): void
	{
		$this->unauthenticate($this->getSessionSection(), $reason);
	}

	/**
	 * @phpstan-param self::REASON_* $reason
	 */
	private function unauthenticate(SessionSection $section, int $reason): void
	{
		$this->session->regenerateId();

		$section->authenticated = false;
		$section->authenticationTime = null;
		$section->logoutReason = $reason;

		$this->removeExpiration();
	}

	public function isLoggedIn(): bool
	{
		if (!$this->session->exists()) {
			return false;
		}

		return $this->getSessionSection()->authenticated;
	}

	public function getLogoutReason(): ?int
	{
		if (!$this->session->exists()) {
			return null;
		}

		return $this->getSessionSection()->logoutReason;
	}

	public function setExpiration(DateTimeInterface $time): void
	{
		$section = $this->getSessionSection();

		$expirationTime = (int) $time->format('U');
		$section->expirationTime = $expirationTime;
		$section->expirationDelta = $delta = $expirationTime - time();

		if ($delta <= 0) {
			$message = Message::create()
				->withContext('Trying to set login expiration time.')
				->withProblem('Expiration time is lower than current time.')
				->withSolution('Choose expiration time which is in future.');

			throw InvalidArgument::create()
				->withMessage($message);
		}

		// Check if login expiration is not greater than session expiration
		$max = (int) ini_get('session.gc_maxlifetime');
		// 0 -> unlimited
		// $max + 2 -> prevent errors from slow code execution
		if ($max !== 0 && ($delta > $max + 2)) {
			$message = Message::create()
				->withContext('Trying to set login expiration time.')
				->withProblem(sprintf(
					'Expiration time %s seconds is greater than the session expiration time of %s seconds.',
					$delta,
					$max,
				))
				->withSolution(
					'Choose expiration time lower than the session expiration time or set higher session expiration time.',
				);

			throw InvalidState::create()
				->withMessage($message);
		}
	}

	public function removeExpiration(): void
	{
		$section = $this->getSessionSection();
		$section->expirationTime = null;
		$section->expirationDelta = null;
	}

	private function getSessionSection(): SessionSection
	{
		if ($this->sessionSection !== null) {
			return $this->sessionSection;
		}

		$sectionName = sprintf('%s.%s', self::SESSION_PREFIX, $this->namespace);

		$isNew = !$this->session->hasSection($sectionName);

		$section = $this->sessionSection = $this->session->getSection($sectionName);
		$section->warnOnUndefined = true;

		if ($isNew) {
			$this->setDefaults($section);
		}

		$identity = $section->identity;

		if ($identity instanceof __PHP_Incomplete_Class) {
			$message = Message::create()
				->withContext('Trying to deserialize data from session.')
				->withProblem(sprintf('Deserialized class %s does not exist.', $identity->__PHP_Incomplete_Class_Name))
				->withSolution(sprintf(
					'Ensure class actually exists and is autoloadable or remove the session with id %s or its invalid section %s',
					$this->session->getId(),
					$sectionName,
				));

			throw InvalidState::create()
				->withMessage($message);
		}

		if ($section->authenticated === true) {
			$this->checkInactivity($section);
			$this->renewIdentity($section);
		}

		return $section;
	}

	private function setDefaults(SessionSection $section): void
	{
		$section->version = 1;

		$section->authenticated = false;
		$section->authenticationTime = null;

		$section->identity = null;

		$section->logoutReason = null;

		$section->expirationTime = null;
		$section->expirationDelta = null;
	}

	private function checkInactivity(SessionSection $section): void
	{
		if ($section->expirationTime === null) {
			return;
		}

		if ($section->expirationTime < time()) {
			$this->unauthenticate($section, self::REASON_INACTIVITY);
		} else {
			$section->expirationTime = time() + $section->expirationDelta;
		}
	}

	private function renewIdentity(SessionSection $section): void
	{
		if ($this->identityRenewer === null) {
			return;
		}

		$identity = $this->identityRenewer->renewIdentity($section->identity);

		if ($identity === null) {
			$this->unauthenticate($section, self::REASON_INVALID_IDENTITY);
		} else {
			$section->identity = $identity;
		}
	}

}
