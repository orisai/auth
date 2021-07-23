<?php declare(strict_types = 1);

namespace Tests\Orisai\Auth\Doubles;

use Brick\DateTime\Clock;
use Orisai\Auth\Authentication\BaseFirewall;
use Orisai\Auth\Authentication\Data\Logins;
use Orisai\Auth\Authentication\Identity;
use Orisai\Auth\Authentication\IdentityRenewer;
use Orisai\Auth\Authentication\LoginStorage;
use Orisai\Auth\Authorization\Authorizer;

/**
 * @phpstan-extends BaseFirewall<Identity>
 */
final class TestingFirewall extends BaseFirewall
{

	private string $namespace;

	public function __construct(
		LoginStorage $storage,
		IdentityRenewer $renewer,
		Authorizer $authorizer,
		?Clock $clock = null,
		string $namespace = 'test'
	)
	{
		parent::__construct($storage, $renewer, $authorizer, $clock);
		$this->namespace = $namespace;
	}

	public function getNamespace(): string
	{
		return $this->namespace;
	}

	public function resetLoginsChecks(): void
	{
		$this->logins = null;
	}

	public function getLogins(): Logins
	{
		return parent::getLogins();
	}

}
