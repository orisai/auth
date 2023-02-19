<?php declare(strict_types = 1);

namespace Orisai\Auth\Authentication\Data;

use __PHP_Incomplete_Class;
use Orisai\Auth\Authentication\LogoutCode;
use Orisai\TranslationContracts\TranslatableMessage;

final class ExpiredLogin extends BaseLogin
{

	private ?Expiration $expiration = null;

	private LogoutCode $logoutCode;

	/** @var string|TranslatableMessage|null */
	private $logoutReason;

	/**
	 * @param string|TranslatableMessage|null $logoutReason
	 */
	public function __construct(
		CurrentLogin $currentLogin,
		LogoutCode $logoutCode,
		$logoutReason = null
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

	/**
	 * @return string|TranslatableMessage|null
	 */
	public function getLogoutReason()
	{
		return $this->logoutReason;
	}

	/**
	 * For compatibility
	 *
	 * @param array<mixed> $data
	 * @return string|TranslatableMessage|null
	 */
	private function getUnserializedLogoutReason(array $data)
	{
		// Reason haven't always existed
		$reason = $data['logoutReasonDescription'] ?? null;

		if (!$reason instanceof __PHP_Incomplete_Class) {
			return $reason;
		}

		// Reason was of type DecisionReason, which was removed
		$reason = (array) $reason;
		if ($reason['translatable'] === true) {
			return new TranslatableMessage($reason['message'], $reason['parameters']);
		}

		return $reason['message'];
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
		$this->logoutReason = $this->getUnserializedLogoutReason($data);
		$this->expiration = $data['expiration'];
	}

}
