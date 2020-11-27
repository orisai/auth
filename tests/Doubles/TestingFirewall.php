<?php declare(strict_types = 1);

namespace Tests\Orisai\Auth\Doubles;

use Orisai\Auth\Authentication\BaseFirewall;
use Orisai\Auth\Authentication\IdentityRenewer;
use Orisai\Auth\Authentication\LoginStorage;

final class TestingFirewall extends BaseFirewall
{

	private string $namespace;

	public function __construct(LoginStorage $storage, ?IdentityRenewer $renewer = null, string $namespace = 'test')
	{
		parent::__construct($storage, $renewer);
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

}
