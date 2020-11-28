<?php declare(strict_types = 1);

namespace Orisai\Auth\Authentication\Data;

use __PHP_Incomplete_Class;
use Brick\DateTime\Instant;
use Orisai\Auth\Authentication\Identity;

abstract class BaseLogin
{

	protected Identity $identity;
	private Instant $authenticationTime;
	private bool $hasInvalidIdentity = false;

	public function __construct(Identity $identity, Instant $authenticationTime)
	{
		$this->identity = $identity;
		$this->authenticationTime = $authenticationTime;
	}

	public function getIdentity(): Identity
	{
		return $this->identity;
	}

	public function getAuthenticationTime(): Instant
	{
		return $this->authenticationTime;
	}

	public function hasInvalidIdentity(): bool
	{
		return $this->hasInvalidIdentity;
	}

	/**
	 * @return array<mixed>
	 */
	public function __serialize(): array
	{
		return [
			'identity' => $this->identity,
			'authenticationTime' => $this->authenticationTime->getEpochSecond(),
		];
	}

	/**
	 * @param array<mixed> $data
	 */
	public function __unserialize(array $data): void
	{
		if ($data['identity'] instanceof __PHP_Incomplete_Class) {
			$this->hasInvalidIdentity = true;
		} else {
			$this->identity = $data['identity'];
		}

		$this->authenticationTime = Instant::of($data['authenticationTime']);
	}

}
