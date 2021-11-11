<?php declare(strict_types = 1);

namespace Orisai\Auth\Authorization;

use Orisai\Exceptions\LogicalException;
use Orisai\Exceptions\Message;

final class UnknownPrivilege extends LogicalException
{

	/**
	 * @param class-string $class
	 */
	public static function forPrivilege(string $privilege, string $class, string $function): self
	{
		$self = new self();

		$message = Message::create()
			->withContext("Trying to call $class->$function().")
			->withProblem("Privilege $privilege is unknown.")
			->withSolution('Add privilege to authorizer first via addPrivilege().');
		$self->withMessage($message);

		return $self;
	}

}
