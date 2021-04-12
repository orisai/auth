<?php declare(strict_types = 1);

namespace Orisai\Auth\Authentication\Data;

use function array_key_last;
use function array_slice;
use function count;

final class Logins
{

	private ?CurrentLogin $currentLogin = null;

	/** @var array<ExpiredLogin> */
	private array $expiredLogins = [];

	public function getCurrentLogin(): ?CurrentLogin
	{
		return $this->currentLogin;
	}

	public function setCurrentLogin(CurrentLogin $currentLogin): void
	{
		$this->currentLogin = $currentLogin;
		$this->removeExpiredLogin($currentLogin->getIdentity()->getId());
	}

	public function removeCurrentLogin(): void
	{
		$this->currentLogin = null;
	}

	public function addExpiredLogin(ExpiredLogin $login): void
	{
		$id = $login->getIdentity()->getId();
		unset($this->expiredLogins[$id]); // Last added login must be last in array
		$this->expiredLogins[$id] = $login;
	}

	/**
	 * @return array<ExpiredLogin>
	 */
	public function getExpiredLogins(): array
	{
		return $this->expiredLogins;
	}

	public function getLastExpiredLogin(): ?ExpiredLogin
	{
		$key = array_key_last($this->expiredLogins);

		if ($key === null) {
			return null;
		}

		return $this->expiredLogins[$key];
	}

	public function removeOldestExpiredLoginsAboveLimit(int $limit): void
	{
		if (($count = count($this->expiredLogins)) <= $limit) {
			return;
		}

		$this->expiredLogins = array_slice($this->expiredLogins, $count - $limit, null, true);
	}

	public function removeExpiredLogins(): void
	{
		$this->expiredLogins = [];
	}

	/**
	 * @param int|string $id
	 */
	public function removeExpiredLogin($id): void
	{
		unset($this->expiredLogins[$id]);
	}

	/**
	 * @return array<mixed>
	 */
	public function __serialize(): array
	{
		return [
			'currentLogin' => $this->currentLogin,
			'expiredLogins' => $this->expiredLogins,
		];
	}

	/**
	 * @param array<mixed> $data
	 */
	public function __unserialize(array $data): void
	{
		$this->currentLogin = $data['currentLogin'];
		$this->expiredLogins = $data['expiredLogins'];

		if ($this->currentLogin !== null && $this->currentLogin->hasInvalidIdentity()) {
			$this->currentLogin = null;
		}

		foreach ($this->expiredLogins as $key => $expiredLogin) {
			if ($expiredLogin->hasInvalidIdentity()) {
				unset($this->expiredLogins[$key]);
			}
		}
	}

}
