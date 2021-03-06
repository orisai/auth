<?php declare(strict_types = 1);

namespace Orisai\Auth\Authentication;

class StringIdentity extends BaseIdentity
{

	protected string $id;

	/**
	 * @param array<string> $roles
	 */
	public function __construct(string $id, array $roles)
	{
		$this->id = $id;
		$this->roles = $roles;
	}

	public function getId(): string
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
