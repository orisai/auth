<?php declare(strict_types = 1);

namespace Tests\Orisai\Auth\Doubles;

use Brick\DateTime\Clock;
use Orisai\Auth\Authentication\BaseFirewall;
use Orisai\Auth\Authentication\Exception\NotLoggedIn;
use Orisai\Auth\Authentication\Firewall;
use Orisai\Auth\Authentication\Identity;
use Orisai\Auth\Authentication\IdentityRenewer;
use Orisai\Auth\Authentication\LoginStorage;
use Orisai\Auth\Authorization\Authorizer;
use Orisai\Auth\Authorization\PolicyManager;

/**
 * @phpstan-extends BaseFirewall<Identity, Firewall>
 */
final class UserAwareFirewall extends BaseFirewall
{

	private UserGetter $userGetter;

	public function __construct(
		UserGetter $userGetter,
		LoginStorage $storage,
		IdentityRenewer $renewer,
		Authorizer $authorizer,
		PolicyManager $policyManager,
		?Clock $clock = null
	)
	{
		parent::__construct($storage, $renewer, $authorizer, $policyManager, $clock);
		$this->userGetter = $userGetter;
	}

	protected function getNamespace(): string
	{
		return 'user-aware';
	}

	public function getUser(): User
	{
		$identity = $this->fetchIdentity();

		if ($identity === null) {
			throw NotLoggedIn::create(self::class, __FUNCTION__);
		}

		$user = $this->userGetter->getUser($identity);

		if ($user === null) {
			throw NotLoggedIn::create(self::class, __FUNCTION__);
		}

		return $user;
	}

}
