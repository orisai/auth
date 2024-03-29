<?php declare(strict_types = 1);

namespace Tests\Orisai\Auth\Doubles;

use Orisai\Auth\Authentication\BaseFirewall;
use Orisai\Auth\Authentication\Data\Logins;
use Orisai\Auth\Authentication\Identity;
use Orisai\Auth\Authentication\IdentityRefresher;
use Orisai\Auth\Authentication\LoginStorage;
use Orisai\Auth\Authorization\Authorizer;
use Orisai\Clock\Clock;

/**
 * @extends BaseFirewall<Identity>
 */
final class TestingFirewall extends BaseFirewall
{

	private string $namespace;

	public function __construct(
		LoginStorage $storage,
		IdentityRefresher $refresher,
		Authorizer $authorizer,
		?Clock $clock = null,
		string $namespace = 'test'
	)
	{
		parent::__construct($storage, $refresher, $authorizer, $clock);
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
