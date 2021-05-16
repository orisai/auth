<?php declare(strict_types = 1);

namespace Orisai\Auth\Authorization;

interface PolicyManager
{

	public function get(string $privilege): ?Policy;

}
