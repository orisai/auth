<?php declare(strict_types = 1);

namespace Orisai\Auth\Authorization;

/**
 * @phpstan-template-covariant P of Policy
 */
interface PolicyManager
{

	/**
	 * @phpstan-return P|null
	 */
	public function get(string $privilege): ?Policy;

}
