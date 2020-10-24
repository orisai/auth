<?php declare(strict_types = 1);

namespace Tests\Orisai\Auth\Doubles;

use DateTimeInterface;
use Orisai\Auth\Authentication\Identity;
use Orisai\Auth\Authentication\IdentityRenewer;
use Orisai\Auth\Authentication\IdentityStorage;

final class ArrayIdentityStorage implements IdentityStorage
{

	private bool $authenticated = false;
	private ?Identity $identity = null;

	/** @phpstan-var self::REASON_*|null */
	private ?int $logoutReason = null;

	private ?DateTimeInterface $expirationTime = null;
	private DateTimeInterface $currentTime;

	private ?IdentityRenewer $identityRenewer;

	public function __construct(DateTimeInterface $currentTime, ?IdentityRenewer $identityRenewer = null)
	{
		$this->currentTime = $currentTime;
		$this->identityRenewer = $identityRenewer;
	}

	public function getIdentity(): ?Identity
	{
		$this->checkAuthentication();

		return $this->identity;
	}

	public function setAuthenticated(Identity $identity): void
	{
		$this->authenticated = true;
		$this->identity = $identity;
		$this->logoutReason = null;
	}

	public function setUnauthenticated(): void
	{
		$this->unauthenticate(self::REASON_MANUAL);
	}

	public function isAuthenticated(): bool
	{
		$this->checkAuthentication();

		return $this->authenticated;
	}

	private function checkAuthentication(): void
	{
		if ($this->authenticated) {
			$this->checkInactivity();
			$this->renewIdentity();
		}
	}

	private function checkInactivity(): void
	{
		if ($this->expirationTime === null) {
			return;
		}

		if ($this->expirationTime < $this->currentTime) {
			$this->unauthenticate(self::REASON_INACTIVITY);
		}
	}

	private function renewIdentity(): void
	{
		if ($this->identityRenewer === null || $this->identity === null) {
			return;
		}

		$identity = $this->identityRenewer->renewIdentity($this->identity);

		if ($identity === null) {
			$this->unauthenticate(self::REASON_INVALID_IDENTITY);
		} else {
			$this->identity = $identity;
		}
	}

	/**
	 * @phpstan-param self::REASON_* $reason
	 */
	private function unauthenticate(int $reason): void
	{
		$this->authenticated = false;
		$this->logoutReason = $reason;

		$this->removeExpiration();
	}

	public function getLogoutReason(): ?int
	{
		$this->checkAuthentication();

		return $this->logoutReason;
	}

	public function setExpiration(DateTimeInterface $time): void
	{
		$this->expirationTime = $time;
	}

	public function removeExpiration(): void
	{
		$this->expirationTime = null;
	}

}
