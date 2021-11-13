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
		$data = parent::__serialize();
		$data['id'] = $this->id;

		return $data;
	}

	/**
	 * @param array<mixed> $data
	 */
	public function __unserialize(array $data): void
	{
		parent::__unserialize($data);
		$this->id = $data['id'];
	}

}
