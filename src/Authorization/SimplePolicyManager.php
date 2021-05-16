<?php declare(strict_types = 1);

namespace Orisai\Auth\Authorization;

/**
 * @phpstan-template P of Policy
 * @phpstan-implements PolicyManager<P>
 */
final class SimplePolicyManager implements PolicyManager
{

	/**
	 * @var array<Policy>
	 * @phpstan-var array<P>
	 */
	private array $policies = [];

	public function get(string $privilege): ?Policy
	{
		return $this->policies[$privilege] ?? null;
	}

	/**
	 * @phpstan-param P $policy
	 * @return $this
	 */
	public function add(Policy $policy): self
	{
		$this->policies[$policy::getPrivilege()] = $policy;

		return $this;
	}

}
