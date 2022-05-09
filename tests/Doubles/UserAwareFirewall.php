<?php declare(strict_types = 1);

namespace Tests\Orisai\Auth\Doubles;

use Brick\DateTime\Clock;
use Orisai\Auth\Authentication\BaseFirewall;
use Orisai\Auth\Authentication\Exception\NotLoggedIn;
use Orisai\Auth\Authentication\Identity;
use Orisai\Auth\Authentication\IdentityRefresher;
use Orisai\Auth\Authentication\LoginStorage;
use Orisai\Auth\Authorization\Authorizer;

/**
 * @phpstan-extends BaseFirewall<Identity>
 */
final class UserAwareFirewall extends BaseFirewall
{

	private UserGetter $userGetter;

	public function __construct(
		UserGetter $userGetter,
		LoginStorage $storage,
		IdentityRefresher $refresher,
		Authorizer $authorizer,
		?Clock $clock = null
	)
	{
		parent::__construct($storage, $refresher, $authorizer, $clock);
		$this->userGetter = $userGetter;
	}

	public function getNamespace(): string
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
