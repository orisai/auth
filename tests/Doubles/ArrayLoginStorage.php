<?php declare(strict_types = 1);

namespace Tests\Orisai\Auth\Doubles;

use DateTimeInterface;
use Orisai\Auth\Authentication\Data\CurrentExpiration;
use Orisai\Auth\Authentication\Data\CurrentLogin;
use Orisai\Auth\Authentication\Data\ExpiredLogin;
use Orisai\Auth\Authentication\Data\Logins;
use Orisai\Auth\Authentication\Exception\CannotRenewIdentity;
use Orisai\Auth\Authentication\Firewall;
use Orisai\Auth\Authentication\Identity;
use Orisai\Auth\Authentication\IdentityRenewer;
use Orisai\Auth\Authentication\LoginStorage;
use Orisai\Exceptions\Logic\ShouldNotHappen;

final class ArrayLoginStorage implements LoginStorage
{

	private int $currentTimestamp;
	private ?IdentityRenewer $identityRenewer;

	private Logins $logins;
	private int $expiredIdentitiesLimit = Firewall::EXPIRED_IDENTITIES_DEFAULT_LIMIT;

	public function __construct(DateTimeInterface $currentTime, ?IdentityRenewer $identityRenewer = null)
	{
		$this->currentTimestamp = (int) $currentTime->format('U');
		$this->identityRenewer = $identityRenewer;
		$this->logins = new Logins();
	}

	public function getIdentity(): ?Identity
	{
		$this->checkAuthentication();
		$currentLogin = $this->logins->getCurrentLogin();

		return $currentLogin === null ? null : $currentLogin->getIdentity();
	}

	public function login(Identity $identity): void
	{
		$previousLogin = $this->logins->getCurrentLogin();
		if ($previousLogin !== null && $previousLogin->getIdentity()->getId() !== $identity->getId()) {
			$this->addExpiredLogin(new ExpiredLogin($previousLogin, $this::REASON_MANUAL));
		}

		$this->logins->setCurrentLogin(new CurrentLogin($identity, $this->currentTimestamp));
	}

	/**
	 * @throws CannotRenewIdentity When user is not logged id
	 */
	public function renewIdentity(Identity $identity): void
	{
		$login = $this->logins->getCurrentLogin();

		if ($login === null) {
			throw CannotRenewIdentity::create(self::class, __FUNCTION__);
		}

		$login->setIdentity($identity);
	}

	public function logout(int $reason): void
	{
		$this->unauthenticate($reason);
	}

	private function checkAuthentication(): void
	{
		$currentLogin = $this->logins->getCurrentLogin();

		if ($currentLogin !== null) {
			$this->checkInactivity($currentLogin);
			$this->checkIdentity($currentLogin);
		}
	}

	private function checkInactivity(CurrentLogin $login): void
	{
		$expiration = $login->getExpiration();

		if ($expiration === null) {
			return;
		}

		if ($expiration->getTimestamp() < $this->currentTimestamp) {
			$this->unauthenticate(self::REASON_INACTIVITY);
		}
	}

	private function checkIdentity(CurrentLogin $login): void
	{
		$identity = $login->getIdentity();

		if ($this->identityRenewer === null || $identity === null) {
			return;
		}

		$identity = $this->identityRenewer->renewIdentity($identity);

		if ($identity === null) {
			$this->unauthenticate(self::REASON_INVALID_IDENTITY);
		} else {
			$login->setIdentity($identity);
		}
	}

	/**
	 * @phpstan-param self::REASON_* $reason
	 */
	private function unauthenticate(int $reason): void
	{
		$login = $this->logins->getCurrentLogin();

		if ($login === null) {
			return;
		}

		$this->logins->removeCurrentLogin();
		$this->addExpiredLogin(new ExpiredLogin($login, $reason));
	}

	/**
	 * @throws ShouldNotHappen When expiration is set before user is logged in and firewall did not check
	 */
	public function setExpiration(DateTimeInterface $time): void
	{
		$login = $this->logins->getCurrentLogin();

		if ($login === null) {
			throw ShouldNotHappen::create()
				->withMessage('Firewall should check whether user is logged in when expiration is set.');
		}

		$expirationTime = (int) $time->format('U');
		$delta = $expirationTime - $this->currentTimestamp;
		$login->setExpiration(new CurrentExpiration($expirationTime, $delta));
	}

	public function removeExpiration(): void
	{
		$login = $this->logins->getCurrentLogin();

		if ($login === null) {
			return;
		}

		$login->removeExpiration();
	}

	private function addExpiredLogin(ExpiredLogin $login): void
	{
		$this->logins->addExpiredLogin($login);
		$this->logins->removeOldestExpiredLoginsAboveLimit($this->expiredIdentitiesLimit);
	}

	/**
	 * @return array<ExpiredLogin>
	 */
	public function getExpiredLogins(): array
	{
		$this->checkAuthentication();

		return $this->logins->getExpiredLogins();
	}

	public function removeExpiredLogins(): void
	{
		$this->logins->removeExpiredLogins();
	}

	/**
	 * @param int|string $id
	 */
	public function removeExpiredLogin($id): void
	{
		$this->logins->removeExpiredLogin($id);
	}

	public function setExpiredIdentitiesLimit(int $count): void
	{
		$this->expiredIdentitiesLimit = $count;
		$this->logins->removeOldestExpiredLoginsAboveLimit($count);
	}

}
