<?php declare(strict_types = 1);

namespace Orisai\Auth\Authentication\Data;

use __PHP_Incomplete_Class;
use Orisai\Auth\Authentication\Identity;
use Orisai\Exceptions\Logic\InvalidState;
use Orisai\Exceptions\Message;
use function sprintf;

abstract class BaseLogin
{

	protected Identity $identity;
	private int $authenticationTimestamp;

	public function __construct(Identity $identity, int $authenticationTimestamp)
	{
		$this->identity = $identity;
		$this->authenticationTimestamp = $authenticationTimestamp;
	}

	public function getIdentity(): Identity
	{
		return $this->identity;
	}

	public function getAuthenticationTimestamp(): int
	{
		return $this->authenticationTimestamp;
	}

	/**
	 * @return array<mixed>
	 */
	public function __serialize(): array
	{
		return [
			'identity' => $this->identity,
			'authenticationTime' => $this->authenticationTimestamp,
		];
	}

	/**
	 * @param array<mixed> $data
	 */
	public function __unserialize(array $data): void
	{
		if ($data['identity'] instanceof __PHP_Incomplete_Class) {
			$message = Message::create()
				->withContext('Trying to deserialize Identity data.')
				->withProblem(
					sprintf('Deserialized class %s does not exist.', $data['identity']->__PHP_Incomplete_Class_Name),
				)
				->withSolution(
					'Ensure class actually exists and is autoloadable or remove logins which use that class from storage.',
				);

			throw InvalidState::create()
				->withMessage($message);
		}

		$this->identity = $data['identity'];
		$this->authenticationTimestamp = $data['authenticationTime'];
	}

}
