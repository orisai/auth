<?php declare(strict_types = 1);

namespace Orisai\Auth\Authorization;

final class SimplePolicyManager implements PolicyManager
{

	/** @var array<Policy> */
	private array $policies = [];

	public function get(string $privilege): ?Policy
	{
		return $this->policies[$privilege] ?? null;
	}

	public function add(Policy $policy): void
	{
		$this->policies[$policy::getPrivilege()] = $policy;
	}

}
