<?php declare(strict_types = 1);

namespace Orisai\Auth\Authentication\Data;

use Orisai\Auth\Authentication\DecisionReason;
use Orisai\Auth\Authentication\Firewall;
use function is_string;

final class ExpiredLogin extends BaseLogin
{

	private ?Expiration $expiration = null;

	/** @phpstan-var Firewall::REASON_* */
	private int $logoutReason;

	private ?DecisionReason $logoutReasonDescription;

	/**
	 * @phpstan-param Firewall::REASON_* $logoutReason
	 */
	public function __construct(
		CurrentLogin $currentLogin,
		int $logoutReason,
		?DecisionReason $logoutReasonDescription = null
	)
	{
		parent::__construct($currentLogin->getIdentity(), $currentLogin->getAuthenticationTime());

		$expiration = $currentLogin->getExpiration();
		if ($expiration !== null) {
			$this->expiration = new Expiration($expiration->getTime(), $expiration->getDelta());
		}

		$this->logoutReason = $logoutReason;
		$this->logoutReasonDescription = $logoutReasonDescription;
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

	public function getLogoutReasonDescription(): ?DecisionReason
	{
		return $this->logoutReasonDescription;
	}

	/**
	 * @return array<mixed>
	 */
	public function __serialize(): array
	{
		$data = parent::__serialize();
		$data['logoutReason'] = $this->logoutReason;
		$data['logoutReasonDescription'] = $this->logoutReasonDescription;
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
		$description = $data['logoutReasonDescription'] ?? null;
		$this->logoutReasonDescription = !is_string($description) ? $description : DecisionReason::create($description);
		$this->expiration = $data['expiration'];
	}

}
