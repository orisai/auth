<?php declare(strict_types = 1);

namespace Orisai\Auth\Authentication\Data;

use Orisai\Auth\Authentication\DecisionReason;
use Orisai\Auth\Authentication\LogoutCode;
use function is_string;

final class ExpiredLogin extends BaseLogin
{

	private ?Expiration $expiration = null;

	private LogoutCode $logoutCode;

	private ?DecisionReason $logoutReason;

	public function __construct(
		CurrentLogin $currentLogin,
		LogoutCode $logoutCode,
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

	public function getLogoutCode(): LogoutCode
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
		$data['logoutReason'] = $this->logoutCode->value;
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
		$this->logoutCode = LogoutCode::from($data['logoutReason']);
		$description = $data['logoutReasonDescription'] ?? null;
		$this->logoutReason = !is_string($description) ? $description : DecisionReason::create($description);
		$this->expiration = $data['expiration'];
	}

}
