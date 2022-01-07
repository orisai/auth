<?php declare(strict_types = 1);

namespace Orisai\Auth\Authentication\Data;

use Orisai\Auth\Authentication\DecisionReason;
use Orisai\Auth\Authentication\Firewall;
use function is_string;

final class ExpiredLogin extends BaseLogin
{

	private ?Expiration $expiration = null;

	/** @phpstan-var Firewall::LOGOUT_* */
	private int $logoutCode;

	private ?DecisionReason $logoutReason;

	/**
	 * @phpstan-param Firewall::LOGOUT_* $logoutCode
	 */
	public function __construct(
		CurrentLogin $currentLogin,
		int $logoutCode,
		?DecisionReason $logoutReason = null
	)
	{
		parent::__construct($currentLogin->getIdentity(), $currentLogin->getAuthenticationTime());

		$expiration = $currentLogin->getExpiration();
		if ($expiration !== null) {
			$this->expiration = new Expiration($expiration->getTime(), $expiration->getDelta());
		}

		$this->logoutCode = $logoutCode;
		$this->logoutReason = $logoutReason;
	}

	public function getExpiration(): ?Expiration
	{
		return $this->expiration;
	}

	/**
	 * @phpstan-return Firewall::LOGOUT_*
	 */
	public function getLogoutCode(): int
	{
		return $this->logoutCode;
	}

	public function getLogoutReason(): ?DecisionReason
	{
		return $this->logoutReason;
	}

	/**
	 * @return array<mixed>
	 */
	public function __serialize(): array
	{
		$data = parent::__serialize();
		$data['logoutReason'] = $this->logoutCode;
		$data['logoutReasonDescription'] = $this->logoutReason;
		$data['expiration'] = $this->expiration;

		return $data;
	}

	/**
	 * @param array<mixed> $data
	 */
	public function __unserialize(array $data): void
	{
		parent::__unserialize($data);
		$this->logoutCode = $data['logoutReason'];
		$description = $data['logoutReasonDescription'] ?? null;
		$this->logoutReason = !is_string($description) ? $description : DecisionReason::create($description);
		$this->expiration = $data['expiration'];
	}

}
