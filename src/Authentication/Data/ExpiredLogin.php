<?php declare(strict_types = 1);

namespace Orisai\Auth\Authentication\Data;

use Orisai\Auth\Authentication\Firewall;

final class ExpiredLogin extends BaseLogin
{

	private ?Expiration $expiration = null;

	/** @phpstan-var Firewall::REASON_* */
	private int $logoutReason;

	/**
	 * @phpstan-param Firewall::REASON_* $logoutReason
	 */
	public function __construct(CurrentLogin $currentLogin, int $logoutReason)
	{
		parent::__construct($currentLogin->getIdentity(), $currentLogin->getAuthenticationTimestamp());

		$expiration = $currentLogin->getExpiration();
		if ($expiration !== null) {
			$this->expiration = new Expiration($expiration->getTimestamp(), $expiration->getDelta());
		}

		$this->logoutReason = $logoutReason;
	}

	public function getExpiration(): ?Expiration
	{
		return $this->expiration;
	}

	/**
	 * @phpstan-return Firewall::REASON_*
	 */
	public function getLogoutReason(): int
	{
		return $this->logoutReason;
	}

	/**
	 * @return array<mixed>
	 */
	public function __serialize(): array
	{
		$data = parent::__serialize();
		$data['logoutReason'] = $this->logoutReason;
		$data['expiration'] = $this->expiration;

		return $data;
	}

	/**
	 * @param array<mixed> $data
	 */
	public function __unserialize(array $data): void
	{
		parent::__unserialize($data);
		$this->logoutReason = $data['logoutReason'];
		$this->expiration = $data['expiration'];
	}

}
