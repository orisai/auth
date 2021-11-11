# Auth

Authentication and authorization

## Content
- [Setup](#setup)
- [Password encoders](#password-encoders)
    - [Sodium](#sodium-encoder)
    - [Bcrypt](#bcrypt-encoder)
	- [Unsafe MD5](#unsafe-md5-encoder)
    - [Backward compatibility](#backward-compatibility---upgrading-encoder)
    - [Extending](#extending)
- [Authentication](#authentication)
    - [Setup](#authentication-setup)
    - [Usage](#authentication-usage)
- [Authorization](#authorization)
	- [Policies](#policies)

## Setup

Install with [Composer](https://getcomposer.org)

```sh
composer require orisai/auth
```

## Password encoders

Encode (hash) and verify passwords.

```php
use Orisai\Auth\Passwords\PasswordEncoder;

final class UserLogin
{

	private PasswordEncoder $passwordEncoder;

	public function __construct(PasswordEncoder $passwordEncoder)
	{
		$this->passwordEncoder = $passwordEncoder;
	}

	public function signIn(string $password): void
	{
		$user; // Query user from database

		if ($this->passwordEncoder->isValid($password, $user->encodedPassword)) {
			$this->updateEncodedPassword($user, $password);

			// Login user
		}
	}

	public function signUp(string $password): void
	{
		$encodedPassword = $this->passwordEncoder->encode($password);

		// Register user
	}

	private function updateEncodedPassword(User $user, string $password): void
	{
		if (!$this->passwordEncoder->needsReEncode($user->encodedPassword)) {
			return;
		}

		$user->encodedPassword = $this->passwordEncoder->encode($password);
	}

}
```

Make sure your passwords storage allows at least 255 characters.
Each algorithm produces encoded strings of different length and even different settings of one algorithms may vary in results.

### Sodium encoder

Hash passwords with **argon2id** algorithm. This encoder is **recommended**.

```php
use Orisai\Auth\Passwords\SodiumPasswordEncoder;

$encoder = new SodiumPasswordEncoder();
```

Options:
- `SodiumPasswordEncoder(?int $timeCost, ?int $memoryCost)`
    - `$timeCost`
        - Maximum number of computations to perform
        - By default is set to higher one of `4` and `SODIUM_CRYPTO_PWHASH_MEMLIMIT_INTERACTIVE`
    - `$memoryCost`
        - Maximum number of memory consumed
        - Defined in bytes
        - By default is set to higher one of `~67 MB` and `SODIUM_CRYPTO_PWHASH_MEMLIMIT_INTERACTIVE`

### Bcrypt encoder

Hash passwords with **bcrypt** algorithm. Unless sodium php extension is not available on your setup then always prefer [sodium encoder](#sodium-encoder).

*Note:* bcrypt algorithm trims password before hashing to 72 characters. You should not worry about it because it does not have any usage impact,
but it may cause issues if you are migrating from a bcrypt-encoder which modified password to be 72 characters or less before hashing, so please ensure produced hashes are same.

```php
use Orisai\Auth\Passwords\BcryptPasswordEncoder;

$encoder = new BcryptPasswordEncoder();
```

Options:
- `BcryptPasswordEncoder(int $cost)`
    - `$cost`
        - Cost of the algorithm
        - Must be in range `4-31`
        - By default is set to `10`

### Unsafe MD5 encoder

**Use only for testing**

Encoding passwords with sodium is safe option, but also time and resource intensive.
For automated tests purposes it may be helpful to choose faster MD5 algorithm which would be **unsafe** in production environment.

```php
use Orisai\Auth\Passwords\UnsafeMD5PasswordEncoder;

$encoder = new UnsafeMD5PasswordEncoder();
```

### Backward compatibility - upgrading encoder

If you are migrating to new algorithm, use `UpgradingPasswordEncoder`.  It requires a preferred encoder and optionally accepts fallback encoders.

If you migrate from a `password_verify()`-compatible password validation method then you don't need any fallback encoders
as it is done automatically for you. These passwords should always start with string like `$2a$`, `$2x$`, `$argon2id$` etc.

If you need fallback to a *custom encoder*, then check [how to implement your own](#extending).

```php
use Orisai\Auth\Passwords\SodiumPasswordEncoder;
use Orisai\Auth\Passwords\UpgradingPasswordEncoder;

// With only preferred encoder
$encoder = new UpgradingPasswordEncoder(
    new SodiumPasswordEncoder()
);

// With outdated fallback encoders
$encoder = new UpgradingPasswordEncoder(
    new SodiumPasswordEncoder(),
    [
        new ExamplePasswordEncoder(),
    ]
);
```

### Extending

While it's not recommended to do so, unless you require it for backward compatibility or deeply understand secure hashing and encryption algorithms,
you can implement own encoder. Simply implement `PasswordEncoder` interface. `BcryptPasswordEncoder` is simple example of a working implementation.

```php
use Orisai\Auth\Passwords\PasswordEncoder;

final class CustomEncoder implements PasswordEncoder
{

	public function encode(string $raw): string
	{
		// An implementation
	}

	public function needsReEncode(string $encoded): bool
	{
		// An implementation
	}

	public function isValid(string $raw, string $encoded): bool
	{
		// An implementation
	}

}
```

## Authentication

Log in user into application via a firewall.

### Authentication setup

Create firewall
- Should extend `BaseFirewall`

```php
<?php

use Orisai\Auth\Authentication\BaseFirewall;

/**
 * @phpstan-extends BaseFirewall<IntIdentity>
 */
final class AdminFirewall extends BaseFirewall
{

	protected function getNamespace(): string
	{
		return 'admin';
	}

}
```

Create an identity renewer
- allows you to log out user on each request at which firewall is used - throw `IdentityExpired` exception
- renews identity on each request so data in user Identity and class itself are always actual

```php
use Orisai\Auth\Authentication\Exception\IdentityExpired;
use Orisai\Auth\Authentication\Identity;
use Orisai\Auth\Authentication\IdentityRenewer;
use Orisai\Auth\Authentication\IntIdentity;

/**
 * @phpstan-implements IdentityRenewer<IntIdentity>
 */
final class AdminIdentityRenewer implements IdentityRenewer
{

    private UserRepository $userRepository;

    public function __construct(UserRepository $userRepository)
    {
        $this->userRepository = $userRepository;
    }

    public function renewIdentity(Identity $identity): Identity
    {
        $user = $this->userRepository->getById($identity->getId());

        if ($user === null) {
            throw IdentityExpired::create();
            //throw IdentityExpired::create('logout reason description');
        }

        return new IntIdentity($user->getId(), $user->getRoles());
    }

}
```

Create firewall instance

```php
use Orisai\Auth\Authorization\PrivilegeAuthorizer;
use Orisai\Auth\Authorization\SimplePolicyManager;
use Orisai\Auth\Bridge\NetteHttp\SessionLoginStorage;

$identityRenewer = new AdminIdentityRenewer($userRepository);
$loginStorage = new SessionLoginStorage($session);
$authorizer = new PrivilegeAuthorizer();
$policyManager = new SimplePolicyManager();
$firewall = new AdminFirewall($loginStorage, $identityRenewer, $authorizer, $policyManager);
```

### Authentication usage

#### Log in user

```php
use Orisai\Auth\Authentication\IntIdentity;

$identity = new IntIdentity($user->getId(), $user->getRoles());
$firewall->login($identity);
$firewall->isLoggedIn(); // true
$firewall->getIdentity(); // $identity
$firewall->getAuthenticationTime(); // Instant
$firewall->getExpirationTime(); // Instant|null
$firewall->hasRole($role); // bool
$firewall->isAllowed($privilege); // bool
```

#### Set or remove login expiration

- Expiration is sliding, each request when firewall is used is expiration extended
- After expiration is user logged out (`ExpiredLogin->getLogoutReason()` returns `$firewall::REASON_INACTIVITY`)

```php
use Brick\DateTime\Instant;

$firewall->setExpiration(Instant::now()->plusDays(7));
$firewall->removeExpiration();
```

#### Renew `Identity`

- use in case you need to change `Identity` on current request (on next request is called `IdentityRenewer`, if set)
- `$firewall->login()` would reset authentication time, don't use it for `Identity` update

```php
use Orisai\Auth\Authentication\IntIdentity;

$identity = new IntIdentity($user->getId(), $user->getRoles());
$firewall->renewIdentity($identity);
```

##### Log out user

- After manual logout `ExpiredLogin->getLogoutReason()` returns `$firewall::REASON_MANUAL`
- `$firewall->getIdentity()` raises an exception, check with `$firewall->isLoggedIn()` or use `$firewall->getExpiredLogins()` instead

```php
$firewall->logout();
$firewall->isLoggedIn(); // false
$firewall->getIdentity(); // exception

$firewall->removeExpiredLogins();
$firewall->setExpiredIdentitiesLimit($count); // Maximum number of expired logins to store, defaults to 3

$firewall->getLastExpiredLogin(); // ExpiredLogin|null
$firewall->getExpiredLogins(); // array<ExpiredLogin>
foreach ($firewall->getExpiredLogins() as $identityId => $expiredLogin) {
    $firewall->removeExpiredLogin($identityId);

    $expiredLogin->getIdentity(); // Identity
    $expiredLogin->getAuthenticationTime(); // Instant
    $expiredLogin->getLogoutReason(); // $firewall::REASON_* - REASON_MANUAL | REASON_INACTIVITY | REASON_INVALID_IDENTITY
    $expiredLogin->getLogoutReasonDescription(); // string|null
    $expiredLogin->getExpiration(); // Expiration|null
}
```

# Authorization

Represent your app permissions with privilege hierarchy

```
✓ article
	✓ view
	✓ publish
	✓ edit
		✓ all
		✓ owned
	✓ delete
```

```php
use Orisai\Auth\Authorization\AuthorizationDataBuilder;
use Orisai\Auth\Authorization\PrivilegeAuthorizer;
use Orisai\Auth\Authorization\SimplePolicyManager;

$policyManager = new SimplePolicyManager();
$authorizer = new PrivilegeAuthorizer($policyManager);
$builder = new AuthorizationDataBuilder();

// Add roles
$builder->addRole('editor');

// Add privileges
//	- they support hierarchy via dot (e.g article.view is part of article)
$builder->addPrivilege('article.view');
$builder->addPrivilege('article.publish');
$builder->addPrivilege('article.delete');
$builder->addPrivilege('article.edit.owned');
$builder->addPrivilege('article.edit.all');

// Allow role to work with specified privileges
$builder->allow('editor', $authorizer::ALL_PRIVILEGES); // Everything
$builder->allow('editor', 'article.edit'); // Everything from article.edit
$builder->allow('editor', 'article'); // Everything from article

// Deny role to work with privileges (you shouldn't need to do this explicitly, everything is disallowed by default)
$builder->deny('editor', 'article');

// Check if user has privilege
$authorizer->isAllowed($identity, 'article'); // bool, required to have all article sub-privileges
$firewall->isAllowed('article'); // shortcut to $authorizer->isAllowed(), but also checks whether user is logged in

// Check privilege is registered
$authorizer->privilegeExists('article'); // bool
```

## Policies

To check whether user has privilege to edit an article, you have to call `$firewall->isAllowed('article.edit')`.
Firewall then (via authorizer) performs checks if user has that privilege and, if any are defined,
also all child privileges like `article.edit.owned` and `article.edit.all`.
This approach is safe but may impractical. To customize that behavior, define a policy:

```php
use Orisai\Auth\Authentication\Identity;
use Orisai\Auth\Authorization\Authorizer;
use Orisai\Auth\Authorization\Policy;

/**
 * @phpstan-implements Policy<Article>
 */
final class ArticleEditPolicy implements Policy
{

	public const EDIT_ALL = 'article.edit.all';

	public static function getPrivilege(): string
	{
		return 'article.edit';
	}

	public static function getRequirementsClass(): string
	{
		return Article::class;
	}

	/**
	 * @param Article $requirements
	 */
	public function isAllowed(Identity $identity, object $requirements, Authorizer $authorizer): bool
	{
		// User is allowed to edit an article, if is allowed to edit all of them or is the article author
		return $authorizer->isAllowed($identity, self::EDIT_ALL)
			|| $authorizer->isAllowed($identity, ...ArticleEditOwnedPolicy::get($requirements));
	}

	/**
	 * @return array{string, object}
	 */
	public static function get(Article $article): array
	{
		return [self::getPrivilege(), $article];
	}

}
```

```php
use Orisai\Auth\Authorization\Authorizer;
use Orisai\Auth\Authentication\Identity;
use Orisai\Auth\Authorization\Policy;

/**
 * @phpstan-implements Policy<Article>
 */
final class ArticleEditOwnedPolicy implements Policy
{

	public static function getPrivilege(): string
	{
		return 'article.edit.owned';
	}

	public static function getRequirementsClass(): string
	{
		return Article::class;
	}

	/**
	 * @param Article $requirements
	 */
	public function isAllowed(Identity $identity, object $requirements, Authorizer $authorizer): bool
	{
		return $authorizer->hasPrivilege($identity, self::getPrivilege())
			&& $identity->getId() === $requirements->getAuthor()->getId();
	}

	/**
	 * @return array{string, object}
	 */
	public static function get(Article $article): array
	{
		return [self::getPrivilege(), $article];
	}

}
```

Now you have to register these policies in policy manager:

- registration example is for `SimplePolicyManager`, other implementations may require different approach

```php
$policyManager->add(new ArticleEditPolicy());
$policyManager->add(new ArticleEditOwnedPolicy());
```

And check if user is allowed by that policy to perform actions:

```php
$firewall->isAllowed(...ArticleEditPolicy::get($article));
```

Be aware that in case of policy firewall itself don't perform any checks except the logged-in check, so you have to do
all the required privilege checks yourself in the policy. It is possible to fallback to default behavior with
`$authorizer->hasPrivilege($identity, self::getPrivilege())`

Once the policy is registered, firewall will require you to pass policy requirements.
You may choose to make requirements nullable and change `object $requirements` to `?object $requirements`.
Other possibility is to not have any requirements at all - in that case use requirement `Orisai\Auth\Authorization\NoRequirement`
and firewall will auto-create it for you.

Always check against the most specific permissions you need. If user is allowed to do everything, `article` privilege
check would be successful, but `ArticleEditOwnedPolicy` check (`article.edit.owned` privilege) may return false in case
user is not author of that article.
