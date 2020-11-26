<?php declare(strict_types = 1);

namespace Orisai\Auth\Authentication\Exception;

use Orisai\Exceptions\LogicalException;
use Orisai\Exceptions\Message;
use function array_pop;
use function explode;
use function sprintf;

final class CannotRenewIdentity extends LogicalException
{

	public static function create(string $class, string $function): self
	{
		$parts = explode('\\', $class);
		$className = array_pop($parts);

		$message = Message::create()
			->withContext(sprintf('Trying to renew identity with %s->%s().', $class, $function))
			->withProblem('User is not logged in firewall.')
			->withSolution(
				sprintf(
					'Use %s->login() instead or check with %s->isLoggedIn().',
					$className,
					$className,
				),
			);

		$self = new self();
		$self->withMessage($message);

		return $self;
	}

}
