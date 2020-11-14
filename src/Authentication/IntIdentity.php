<?php declare(strict_types = 1);

namespace Orisai\Auth\Authentication;

final class IntIdentity extends BaseIdentity
{

	private int $id;

	/**
	 * @param array<string> $roles
	 */
	public function __construct(int $id, array $roles)
	{
		$this->id = $id;
		$this->roles = $roles;
	}

	public function getId(): int
	{
		return $this->id;
	}

	/**
	 * @return array<mixed>
	 */
	public function __serialize(): array
	{
		return [
			'id' => $this->id,
			'roles' => $this->roles,
		];
	}

	/**
	 * @param array<mixed> $data
	 */
	public function __unserialize(array $data): void
	{
		$this->id = $data['id'];
		$this->roles = $data['roles'];
	}

}
