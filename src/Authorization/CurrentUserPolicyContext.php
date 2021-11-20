<?php declare(strict_types = 1);

namespace Orisai\Auth\Authorization;

use Orisai\Auth\Authentication\Data\ExpiredLogin;
use Orisai\Auth\Authentication\Firewall;
use Orisai\Auth\Authentication\Identity;

final class CurrentUserPolicyContext implements PolicyContext
{

	private Authorizer $authorizer;

	/** @var Firewall<Identity> */
	private Firewall $firewall;

	/**
	 * @param Firewall<Identity> $firewall
	 *
	 * @internal
	 */
	public function __construct(Authorizer $authorizer, Firewall $firewall)
	{
		$this->authorizer = $authorizer;
		$this->firewall = $firewall;
	}

	public function getAuthorizer(): Authorizer
	{
		return $this->authorizer;
	}

	/**
	 * @return array<ExpiredLogin>
	 */
	public function getExpiredLogins(): array
	{
		return $this->firewall->getExpiredLogins();
	}

}
