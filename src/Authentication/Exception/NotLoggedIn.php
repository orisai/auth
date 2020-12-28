<?php declare(strict_types = 1);

namespace Orisai\Auth\Authentication\Exception;

use Orisai\Auth\Authentication\Firewall;
use Orisai\Auth\Authentication\Identity;
use Orisai\Exceptions\LogicalException;
use Orisai\Exceptions\Message;
use function array_pop;
use function explode;

final class NotLoggedIn extends LogicalException
{

	/**
	 * @param class-string<Firewall<Identity>> $class
	 */
	public static function create(string $class, string $function): self
	{
		$parts = explode('\\', $class);
		$className = array_pop($parts);

		$message = Message::create()
			->withContext("Calling {$class}->{$function}().")
			->withProblem('User is not logged in firewall.')
			->withSolution("Login with {$className}->login(\$identity) or check with {$className}->isLoggedIn().");

		$self = new self();
		$self->withMessage($message);

		return $self;
	}

}
