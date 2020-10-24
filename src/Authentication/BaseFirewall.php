<?php declare(strict_types = 1);

namespace Orisai\Auth\Authentication;

use DateTimeInterface;
use Orisai\Exceptions\Logic\InvalidState;
use Orisai\Exceptions\Message;
use function array_pop;
use function explode;
use function sprintf;

abstract class BaseFirewall implements Firewall
{

	private IdentityStorage $storage;

	public function __construct(IdentityStorage $storage)
	{
		$this->storage = $storage;
	}

	public function isLoggedIn(): bool
	{
		return $this->storage->isAuthenticated();
	}

	public function login(Identity $identity): void
	{
		$this->storage->setAuthenticated($identity);
	}

	public function logout(): void
	{
		$this->storage->setUnauthenticated();
	}

	public function getLogoutReason(): ?int
	{
		return $this->storage->getLogoutReason();
	}

	public function getIdentity(): Identity
	{
		$identity = $this->getExpiredIdentity();

		if ($identity === null || !$this->isLoggedIn()) {
			$parts = explode('\\', static::class);
			$className = array_pop($parts);

			$message = Message::create()
				->withContext(sprintf('Trying to get valid identity with %s->%s().', static::class, __FUNCTION__))
				->withProblem('User is not logged in firewall.')
				->withSolution(
					sprintf(
						'Check with %s->isLoggedIn() or use %s->getExpiredIdentity().',
						$className,
						$className,
					),
				);

			throw InvalidState::create()
				->withMessage($message);
		}

		return $identity;
	}

	public function getExpiredIdentity(): ?Identity
	{
		return $this->storage->getIdentity();
	}

	public function setExpiration(DateTimeInterface $time): void
	{
		$this->storage->setExpiration($time);
	}

	public function removeExpiration(): void
	{
		$this->storage->removeExpiration();
	}

}
