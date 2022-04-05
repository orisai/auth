<?php declare(strict_types = 1);

namespace Orisai\Auth\Authorization;

use Orisai\Auth\Authentication\Firewall;
use Orisai\Auth\Authentication\Identity;

final class CurrentUserPolicyContextCreator
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
		$this->firewall = $firewall;
	}

	public function create(): CurrentUserPolicyContext
	{
		return new CurrentUserPolicyContext($this->firewall);
	}

}
