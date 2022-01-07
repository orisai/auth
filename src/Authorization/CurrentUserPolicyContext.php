<?php declare(strict_types = 1);

namespace Orisai\Auth\Authorization;

use Orisai\Auth\Authentication\Data\ExpiredLogin;
use Orisai\Auth\Authentication\Firewall;
use Orisai\Auth\Authentication\Identity;

final class CurrentUserPolicyContext extends BaseUserPolicyContext
{

	/** @var Firewall<Identity> */
	private Firewall $firewall;

	/**
	 * @param Firewall<Identity> $firewall
	 *
	 * @internal
	 */
	public function __construct(Firewall $firewall)
	{
		parent::__construct($firewall->getAuthorizer());
		$this->firewall = $firewall;
	}

	/**
	 * @return array<ExpiredLogin>
	 */
	public function getExpiredLogins(): array
	{
		return $this->firewall->getExpiredLogins();
	}

}
