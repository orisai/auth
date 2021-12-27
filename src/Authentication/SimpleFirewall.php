<?php declare(strict_types = 1);

namespace Orisai\Auth\Authentication;

use Brick\DateTime\Clock;
use Orisai\Auth\Authorization\Authorizer;

/**
 * @phpstan-extends BaseFirewall<Identity>
 */
final class SimpleFirewall extends BaseFirewall
{

	private string $namespace;

	public function __construct(
		string $namespace,
		LoginStorage $storage,
		IdentityRefresher $refresher,
		Authorizer $authorizer,
		?Clock $clock = null
	)
	{
		parent::__construct($storage, $refresher, $authorizer, $clock);
		$this->namespace = $namespace;
	}

	protected function getNamespace(): string
	{
		return $this->namespace;
	}

}
