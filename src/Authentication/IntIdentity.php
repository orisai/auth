<?php declare(strict_types = 1);

namespace Orisai\Auth\Authentication;

class IntIdentity extends BaseIdentity
{

	private int $id;

	/**
	 * @param array<int, string> $roles
	 */
	public function __construct(int $id, array $roles)
	{
		parent::__construct($roles);
		$this->id = $id;
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
