<?php declare(strict_types = 1);

namespace Orisai\Auth\Authentication\Data;

use Orisai\Auth\Authentication\Identity;

final class CurrentLogin extends BaseLogin
{

	private ?CurrentExpiration $expiration = null;

	public function setIdentity(Identity $identity): void
	{
		$this->identity = $identity;
	}

	public function getExpiration(): ?CurrentExpiration
	{
		return $this->expiration;
	}

	public function setExpiration(CurrentExpiration $expiration): void
	{
		$this->expiration = $expiration;
	}

	public function removeExpiration(): void
	{
		$this->expiration = null;
	}

	/**
	 * @return array<mixed>
	 */
	public function __serialize(): array
	{
		$data = parent::__serialize();
		$data['expiration'] = $this->expiration;

		return $data;
	}

	/**
	 * @param array<mixed> $data
	 */
	public function __unserialize(array $data): void
	{
		parent::__unserialize($data);
		$this->expiration = $data['expiration'];
	}

}
