# Auth

Authentication and authorization

## Content
- [Setup](#setup)
- [Password encoders](#password-encoders)
    - [Sodium](#sodium-encoder)
    - [Bcrypt](#bcrypt-encoder)
    - [Backward compatibility](#backward-compatibility---upgrading-encoder)
    - [Extending](#extending)
- [Authentication](#authentication)
    - [Setup](#authentication-setup)
    - [Usage](#authentication-usage)

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

final class AdminFirewall extends BaseFirewall
{

	protected function getNamespace(): string
	{
		return 'admin';
	}

}
```

Create an identity renewer
- allows you to log out user on each request at which firewall is used - return null
- renews identity on each request so data in user Identity and class itself are always actual

```php
use Orisai\Auth\Authentication\Identity;
use Orisai\Auth\Authentication\IdentityRenewer;
use Orisai\Auth\Authentication\IntIdentity;

final class AdminIdentityRenewer implements IdentityRenewer
{

    private UserRepository $userRepository;

    public function __construct(UserRepository $userRepository)
    {
        $this->userRepository = $userRepository;
    }

    public function renewIdentity(Identity $identity): ?Identity
    {
        $user = $this->userRepository->getById($identity->getId());

        if ($user === null) {
            return null;
        }

        return new IntIdentity($user->getId(), $user->getRoles());
    }

}
```

Create firewall instance

```php
use Orisai\Auth\Bridge\NetteHttp\NetteSessionLoginStorage;

$identityRenewer = new AdminIdentityRenewer($userRepository);
$loginStorage = new NetteSessionLoginStorage($session);
$firewall = new AdminFirewall($loginStorage, $identityRenewer);
```

### Authentication usage

#### Log in user

```php
use Orisai\Auth\Authentication\IntIdentity;

$identity = new IntIdentity($user->getId(), $user->getRoles());
$firewall->login($identity);
$firewall->isLoggedIn(); // true
$firewall->getIdentity(); // $identity
```

#### Set or remove login expiration

- Expiration is sliding, each request when firewall is used is expiration extended
- After expiration is user logged out (`ExpiredLogin->getLogoutReason()` returns `$firewall::REASON_INACTIVITY`)

```php
$firewall->setExpiration(new DateTimeImmutable('1 week'));
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

$firewall->getExpiredLogins(); // array<ExpiredLogin>
foreach ($firewall->getExpiredLogins() as $identityId => $expiredLogin) {
    $firewall->removeExpiredLogin($identityId);

    $expiredLogin->getIdentity(); // Identity
    $expiredLogin->getAuthenticationTimestamp(); // int
    $expiredLogin->getLogoutReason(); // $firewall::REASON_* - REASON_MANUAL | REASON_INACTIVITY | REASON_INVALID_IDENTITY
    $expiredLogin->getExpiration(); // Expiration|null
}
```

