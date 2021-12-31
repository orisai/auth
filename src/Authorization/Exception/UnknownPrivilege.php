<?php declare(strict_types = 1);

namespace Orisai\Auth\Authorization\Exception;

use Orisai\Exceptions\LogicalException;
use Orisai\Exceptions\Message;

final class UnknownPrivilege extends LogicalException
{

	private string $privilege;

	private function __construct(string $privilege)
	{
		/** @infection-ignore-all */
		parent::__construct();
		$this->privilege = $privilege;
	}

	/**
	 * @param class-string $class
	 */
	public static function forFunction(string $privilege, string $class, string $function): self
	{
		$self = new self($privilege);

		$message = Message::create()
			->withContext("Trying to call $class->$function().")
			->withProblem("Privilege '$privilege' is unknown.")
			->withSolution('Add privilege to data builder first via addPrivilege().');
		$self->withMessage($message);

		return $self;
	}

	public function getPrivilege(): string
	{
		return $this->privilege;
	}

}
