<?php declare(strict_types = 1);

namespace Tests\Orisai\Auth\Doubles;

use Brick\DateTime\Clock;
use Orisai\Auth\Authentication\BaseFirewall;
use Orisai\Auth\Authentication\Data\Logins;
use Orisai\Auth\Authentication\Firewall;
use Orisai\Auth\Authentication\Identity;
use Orisai\Auth\Authentication\IdentityRenewer;
use Orisai\Auth\Authentication\LoginStorage;
use Orisai\Auth\Authorization\Authorizer;
use Orisai\Auth\Authorization\PolicyManager;

/**
 * @phpstan-extends BaseFirewall<Identity, Firewall>
 */
final class TestingFirewall extends BaseFirewall
{

	private string $namespace;

	public function __construct(
		LoginStorage $storage,
		IdentityRenewer $renewer,
		Authorizer $authorizer,
		PolicyManager $policyManager,
		?Clock $clock = null,
		string $namespace = 'test'
	)
	{
		parent::__construct($storage, $renewer, $authorizer, $policyManager, $clock);
		$this->namespace = $namespace;
	}

	protected function getNamespace(): string
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
