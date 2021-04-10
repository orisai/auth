<?php declare(strict_types = 1);

namespace Tests\Orisai\Auth\Doubles;

use Orisai\Auth\Authentication\Identity;

final class UserGetter
{

	/** @var array<int|string, User> */
	private array $users = [];

	public function addUser(User $user): void
	{
		$this->users[$user->getId()] = $user;
	}

	public function getUser(Identity $identity): ?User
	{
		return $this->users[$identity->getId()] ?? null;
	}

}
