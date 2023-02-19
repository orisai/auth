# Auth

Authentication and authorization

## Content

- [Setup](#setup)
- [Authentication](#authentication)
	- [Setup](#authentication-setup)
	- [Identity](#identity)
	- [Log-in](#log-in)
	- [Log-in expiration](#log-in-expiration)
	- [Identity refreshing](#identity-refreshing)
	- [Log-out](#log-out)
	- [Fetch database user](#fetch-database-user)
	- [Expired logins](#expired-logins)
	- [Login storage](#login-storage)
	- [Separate login for each application section](#separate-login-for-each-application-section)
- [Authorization](#authorization)
	- [Setup](#authorization-setup)
		- [Verifying privileges on assign](#verifying-privileges-on-assign)
	- [Roles](#roles)
	- [Privileges](#privileges)
		- [Identity privileges](#identity-privileges)
	- [Policies - customized authorization](#policies---customized-authorization)
		- [Policy context](#policy-context)
		- [Policy with optional log-in check](#policy-with-optional-log-in-check)
		- [Policy with optional requirements](#policy-with-optional-requirements)
		- [Policy with no requirements](#policy-with-no-requirements)
		- [Policy with default-like privilege check](#policy-with-default-like-privilege-check)
	- [Root - bypass all checks](#root---bypass-all-checks)
	- [Check authorization of not current user](#check-authorization-of-not-current-user)
	- [Access entries](#access-entries)
	- [Access data](#access-authorization-data)
- [Passwords](#passwords)
	- [Argon2](#argon2-hasher)
	- [Bcrypt](#bcrypt-hasher)
	- [Backward compatibility - upgrading when user logs in](#backward-compatibility---upgrading-when-user-logs-in)
	- [Backward compatibility - migrating from an unsafe algorithm](#backward-compatibility---migrating-from-an-unsafe-algorithm)

## Setup

Install with [Composer](https://getcomposer.org)

```sh
composer require orisai/auth
```

Check [authentication](#authentication), [authorization](#authorization) and [passwords](#passwords) for their
individual setup.

## Authentication

[Log-in](#log-in), [log-out](#log-out), access [expired log-ins](#expired-logins) and check *current*
user [permissions](#authorization) to perform actions via Firewall interface.

### Authentication setup

Create a firewall, with following dependencies:

- Namespace - a unique identifier, used to separate logins of each firewall in login storage
- [Login storage](#login-storage) - choose one of available or implement your own
- [Identity refresher](#identity-refreshing) - implement your own, it is required to keep user login up-to-date
- [Authorizer](#authorization) - authorizer can be left not configured for authentication, it is used only for privilege
  and policy-based authorization

```php
use Orisai\Auth\Authentication\ArrayLoginStorage;
use Orisai\Auth\Authentication\SimpleFirewall;
use Orisai\Auth\Authorization\AuthorizationDataBuilder;
use Orisai\Auth\Authorization\AuthorizationData;
use Orisai\Auth\Authorization\PrivilegeAuthorizer;
use Orisai\Auth\Authorization\SimplePolicyManager;

$loginStorage = new ArrayLoginStorage();
$identityRefresher = new ExampleIdentityRefresher();
$authorizer = new PrivilegeAuthorizer(
	new SimplePolicyManager(),
	(new AuthorizationDataBuilder())->build(),
);
$firewall = new SimpleFirewall(
	'namespace',
	$loginStorage,
	$identityRefresher,
	$authorizer,
);
```

### Identity

Identity is a storage for user unique ID and authorization-related data - [roles](#roles) and
user-specific [privileges](#privileges).

It is required for [logging into firewall](#log-in) and authorization via [authorizer](#authorization).

For numeric ID:

```php
use Orisai\Auth\Authentication\IntIdentity;

$identity = new IntIdentity(123, ['list', 'of', 'roles']);
```

For string ID (e.g. UUID/ULID):

```php
use Orisai\Auth\Authentication\StringIdentity;

$identity = new StringIdentity('1fdc5f77-4254-4888-99b2-bce81bb4fa39', ['list', 'of', 'roles']);
```

You can also extend `Orisai\Auth\Authentication\BaseIdentity` or implement `Orisai\Auth\Authentication\Identity` to
store additional data into identity. But usually it's more convenient
to [get user data from database](#fetch-database-user).

### Log-in

Log-in user:

```php
$firewall->login($identity);
```

Firewall itself does **no credentials checks**, you have to log-in user with an [identity](#identity) you already
verified user has access to.

After log-in, several methods become accessible:

```php
$firewall->isLoggedIn() // true
if ($firewall->isLoggedIn()) {
	$firewall->getIdentity(); // Identity

	$firewall->getAuthenticationTime(); // DateTimeImmutable
	$firewall->getExpirationTime(); // DateTimeImmutable
	$firewall->setExpirationTime($datetime); // void

	$firewall->refreshIdentity($newIdentity); // void
}
```

You can listen to log-in via callback:

```php
$firewall->addLoginCallback(function() use($firewall): void {
	// After log-in
});
```

### Log-in expiration

Set login to expire after certain amount of time. Expiration is sliding, each request in which firewall is used,
expiration is extended.

```php
use DateTimeImmutable;

$firewall->setExpiration(new DateTimeImmutable('7 days'));
$firewall->removeExpiration();
```

Firewall uses a `Psr\Clock\ClockInterface` instance for getting time, you may set custom instance through constructor
for testing expiration with fixed time. Check [orisai/clock](https://github.com/orisai/clock) for available
implementations.

### Identity refreshing

Identity is refreshed on each request through an `IdentityRefresher` to keep roles and privileges of active logins
up-to-date.

```php
use Example\Core\User\UserRepository;
use Orisai\Auth\Authentication\Exception\IdentityExpired;
use Orisai\Auth\Authentication\Identity;
use Orisai\Auth\Authentication\IdentityRefresher;
use Orisai\Auth\Authentication\IntIdentity;

/**
 * @phpstan-implements IdentityRefresher<IntIdentity>
 */
final class AdminIdentityRefresher implements IdentityRefresher
{

    private UserRepository $userRepository;

    public function __construct(UserRepository $userRepository)
    {
        $this->userRepository = $userRepository;
    }

    public function refresh(Identity $identity): Identity
    {
        $user = $this->userRepository->getById($identity->getId());

		// User no longer exists, log them out
        if ($user === null) {
            throw IdentityExpired::create();
        }

        return new IntIdentity($user->id, $user->roles);
    }

}
```

`IdentityExpired` exception accepts parameter with reason why user was logged out. Together with logout code is
accessible through [expired login](#expired-logins):

```php
use Orisai\Auth\Authentication\Exception\IdentityExpired;
use Orisai\TranslationContracts\TranslatableMessage;

throw IdentityExpired::create('decision reason');
// or
throw IdentityExpired::create(new TranslatableMessage('decision.reason.key'));
```

Identity can be refreshed also manually on current request. Unlike `$firewall->login()` it keeps the previous
authentication and expiration times.

```php
use Orisai\Auth\Authentication\IntIdentity;

$identity = new IntIdentity($user->getId(), $user->getRoles());
$firewall->refreshIdentity($identity);
```

### Log-out

Manual log-out:

```php
$firewall->logout();
```

User is automatically logged-out in case their [login expired](#log-in-expiration)
or [identity refresher](#identity-refreshing) invalidated identity.

Several methods are accessible only for logged-in users and should be preceded by `isLoggedIn()` check:

```php
$firewall->isLoggedIn() // false
if (!$firewall->isLoggedIn()) {
	$firewall->getIdentity(); // exception

	$firewall->getAuthenticationTime(); // exception
	$firewall->getExpirationTime(); // exception
	$firewall->setExpirationTime($datetime); // exception

	$firewall->refreshIdentity($newIdentity); // exception
}
```

You can listen to *any* if the log-out methods via callback:

```php
$firewall->addLogoutCallback(function() use($firewall): void {
	// After log-out
});
```

### Fetch database user

Get user entity directly from firewall

```php
use Example\Core\User\UserRepository;
use Orisai\Auth\Authentication\BaseFirewall;
use Orisai\Auth\Authentication\Exception\NotLoggedIn;
use Orisai\Auth\Authentication\IdentityRefresher;
use Orisai\Auth\Authentication\LoginStorage;
use Orisai\Auth\Authorization\Authorizer;
use Psr\Clock\ClockInterface;

final class UserAwareFirewall extends BaseFirewall
{

	private UserRepository $userRepository;

	public function __construct(
		UserRepository $userRepository,
		LoginStorage $storage,
		IdentityRefresher $refresher,
		Authorizer $authorizer,
		?ClockInterface $clock = null
	) {
		parent::__construct($storage, $refresher, $authorizer, $clock);
		$this->userRepository = $userRepository;
	}

	public function getUser(): User
	{
		$identity = $this->fetchIdentity();

		// Method can't be used for logged-out user
		if ($identity === null) {
			throw NotLoggedIn::create(static::class, __FUNCTION__);
		}

		return $this->userRepository->getByIdChecked($identity->getId());
	}

}
```

### Expired logins

After user is logged out you may still access all data about this login. This way you may e.g. offer user to log back
into their account.

```php
use Orisai\TranslationContracts\TranslatableMessage;
use Orisai\TranslationContracts\Translator;

$expiredLogin = $firewall->getLastExpiredLogin();

if ($expiredLogin !== null) {
	$identity = $expiredLogin->getIdentity(); // Identity

	$authenticationTime = $expiredLogin->getAuthenticationTime(); // DateTimeImmutable
	$expiration = $expiredLogin->getExpiration();
	$expirationTime = $expiration !== null ? $expiration->getTime() : null; // DateTimeImmutable|null

	$logoutCode = $expiredLogin->getLogoutCode(); // LogoutCode
	$logoutReason = $expiredLogin->getLogoutReason(); // string|TranslatableMessage|null

	if ($logoutReason !== null) {
		$message = $logoutReason->getMessage();
		if ($message instanceof TranslatableMessage) {
			assert($translator instanceof Translator); // Create translator or get message id and parameters from TranslatableMessage
			$message = $translator->translateMessage($message);
		}
	}
}
```

Access all expired logins, ordered from oldest to newest:

```php
foreach ($firewall->getExpiredLogins() as $identityId => $expiredLogin) {
	// ...
}
```

Remove all expired logins:

```php
$firewall->removeExpiredLogins();
```

Remove expired login by ID from `Identity` - for one ID is always stored only the newest:

```php
$firewall->removeExpiredLogin($identityId);
```

Only 3 expired identities are stored by default. These out of limit are removed from the oldest. To change the limit,
call:

```php
$firewall->setExpiredIdentitiesLimit(0);
```

### Login storage

Information about current login and expired logins has to be stored somewhere. For this purpose you may use two types of
storages - for single request and across requests.

Single request storage is useful for APIs where user authorizes with each request. For this purpose use:

- `Orisai\Auth\Authentication\ArrayLoginStorage`

For standard across requests authentication:

- `OriNette\Auth\SessionLoginStorage` (from [orisai/nette-auth](https://github.com/orisai/nette-auth) package, uses
  session mechanism from [nette/http](https://github.com/nette/http))

### Separate login for each application section

Each section of application, like administration, frontend and API can have fully separate login. For each section you
just need to create firewall instance, with a unique *namespace*.

Namespace of a firewall can be accessed via `$firewall->getNamespace();`.

`SimpleFirewall` accepts *namespace* in constructor, yet it may be more convenient to extend `BaseFirewall` and
differentiate each firewall by class name.

```php
<?php

use Orisai\Auth\Authentication\BaseFirewall;

/**
 * @phpstan-extends BaseFirewall<IntIdentity>
 */
final class AdminFirewall extends BaseFirewall
{

	public function getNamespace(): string
	{
		return 'admin';
	}

}
```

## Authorization

Check *any* user [permissions](#authorization) to perform actions via [privilege](#privileges)-based system.

```php
$firewall->isAllowed('privilege');
$authorizer->isAllowed($identity, 'privilege');
```

User has no access to anything, unless explicitly allowed by [privilege](#privileges) or
by [policy](#policies---customized-authorization).

### Authorization setup

As a first step, create an authorizer, a policy manager and empty authorization data:

```php
use Orisai\Auth\Authorization\AuthorizationData;
use Orisai\Auth\Authorization\AuthorizationDataBuilder;
use Orisai\Auth\Authorization\AuthorizationDataCreator;
use Orisai\Auth\Authorization\PrivilegeAuthorizer;
use Orisai\Auth\Authorization\SimpleAuthorizationDataCreator;
use Orisai\Auth\Authorization\SimplePolicyManager;

$dataBuilder = new AuthorizationDataBuilder();
$dataCreator = new SimpleAuthorizationDataCreator($dataBuilder);
$policyManager = new SimplePolicyManager();
$authorizer = new PrivilegeAuthorizer($policyManager, $dataCreator);
```

Step 2 (optional):

- Create data builder
- Add [privileges](#privileges) and [roles](#roles)
- Assign privileges to roles
- Build the data

```php
use Orisai\Auth\Authorization\AuthorizationData;
use Orisai\Auth\Authorization\AuthorizationDataBuilder;
use Orisai\Auth\Authorization\Authorizer;

// Create data builder
$dataBuilder = new AuthorizationDataBuilder();

// Add privileges
$dataBuilder->addPrivilege('article.delete');
$dataBuilder->addPrivilege('article.edit.all');
$dataBuilder->addPrivilege('article.edit.owned');
$dataBuilder->addPrivilege('article.publish');

// Add roles
$dataBuilder->addRole('editor');
$dataBuilder->addRole('chief-editor');
$dataBuilder->addRole('supervisor');

// Allow role to work with specified privileges
$dataBuilder->allow('chief-editor', 'article.edit'); // Edit both owned and all articles
$dataBuilder->allow('chief-editor', 'article.publish'); // Publish article
$dataBuilder->allow('chief-editor', 'article.delete'); // Delete articles
$dataBuilder->allow('editor', 'article.edit.owned'); // Edit owned articles

// Give role a root access
$dataBuilder->addRoot('supervisor');

// Create data object
$data = $dataBuilder->build();
```

Step 3 (optional):

- Abstract data creation with an object

```php
use Orisai\Auth\Authorization\PrivilegeAuthorizer;
use Orisai\Auth\Authorization\SimplePolicyManager;

$dataCreator = new AuthorizationDataCreatorImpl();
$policyManager = new SimplePolicyManager();
$authorizer = new PrivilegeAuthorizer($policyManager, $dataCreator);
```

```php
use Orisai\Auth\Authorization\AuthorizationData;
use Orisai\Auth\Authorization\AuthorizationDataBuilder;
use Orisai\Auth\Authorization\AuthorizationDataCreator;
use Orisai\Auth\Authorization\Authorizer;

final class AuthorizationDataCreatorImpl implements AuthorizationDataCreator
{

	public function create(): AuthorizationData
	{
		$dataBuilder = new AuthorizationDataBuilder();

		foreach ($this->getPrivileges() as $privilege) {
			// $dataBuilder->addPrivilege('article.publish');
			$dataBuilder->addPrivilege($privilege);
		}

		foreach ($this->getRolePrivileges() as $role => $privileges) {
			// $dataBuilder->addRole('chief-editor');
			$dataBuilder->addRole($role);

			if ($privileges === true) {
				$dataBuilder->addRoot($role);
			} else {
				foreach ($privileges as $privilege) {
					// $dataBuilder->allow('chief-editor', 'article.publish');
					$dataBuilder->allow($role, $privilege);
				}
			}

		}

		return $dataBuilder->build();
	}

	/**
	 * @return array<string>
	 */
	private function getPrivileges(): array
	{
		return [
			'article.delete',
			'article.edit.all',
			'article.edit.owned',
			'article.publish',
		];
	}

	/**
	 * @return array<string, true|array<string>>
	 */
	private function getRolePrivileges(): array
	{
		return [
			'supervisor' => true,
			'editor' => [
				'article.edit.owned',
			],
			'chief-editor' => [
				'article.delete',
				'article.edit',
				'article.publish',
			],
		];
	}

}
```

Step 4 (optional):

- Move privileges to an external source (config, editable by programmer)
- Move roles and their privileges to an external source (database, editable by system supervisor)
- Cache created data - instead of building data on each request, serialize them in cache and invalidate on change

```php
namespace Example\Core\Auth;

use Example\Core\Role\RoleRepository;
use ExampleLib\Caching\Cache;
use Orisai\Auth\Authorization\AuthorizationData;
use Orisai\Auth\Authorization\AuthorizationDataBuilder;
use Orisai\Auth\Authorization\AuthorizationDataCreator;

final class AuthorizationDataCreator implements AuthorizationDataCreator
{

	private const CacheKey = 'Example.Core.Auth.Data';

	/** @var array<string> */
	private array $privileges;

	private RoleRepository $roleRepository;

	private Cache $cache;

	/**
	 * @param array<string> $privileges
	 */
	public function __construct(array $privileges, RoleRepository $roleRepository, Cache $cache)
	{
		$this->privileges = $privileges;
		$this->roleRepository = $roleRepository;
		$this->cache = $cache;

		$this->roleRepository->onFlush[] = fn () => $this->rebuild();
	}

	public function create(): AuthorizationData
	{
		$data = $this->cache->load(self::CacheKey);
		if ($data instanceof AuthorizationData) {
			return $data;
		}

		$data = $this->buildData();

		$this->cache->save(self::CacheKey, $data);

		return $data;
	}

	private function rebuild(): void
	{
		$data = $this->buildData();
		$this->cache->save(self::CacheKey, $data);
	}

	private function buildData(): AuthorizationData
	{
		$dataBuilder = new AuthorizationDataBuilder();

		foreach ($this->privileges as $privilege) {
			$dataBuilder->addPrivilege($privilege);
		}

		$roles = $this->roleRepository->findAll();

		foreach ($roles as $role) {
			$dataBuilder->addRole($role->name);

			if ($role->root) {
				$dataBuilder->addRoot($role->name);
			}

			foreach ($role->privileges as $privilege) {
				$dataBuilder->allow($role->name, $privilege);
			}
		}

		return $dataBuilder->build();
	}

}
```

#### Verifying privileges on assign

When an unknown privilege is assigned to role or identity, an exception is thrown. This behavior is correct, but it also
means you have to migrate assigned privileges when you remove or rename one.

If it is too complicated, you may just turn it off and re-assign renamed privileges to user:

> This is just a workaround, preferably never use this option

```php
use Orisai\Auth\Authorization\AuthorizationDataBuilder;

$dataBuilder = new AuthorizationDataBuilder();
$dataBuilder->throwOnUnknownPrivilege = false;

// ...

$data = $dataBuilder->build();
```

### Roles

User roles like developer, admin and editor are the most basic form of authorization. User can have multiple roles
assigned through their identity.

```php
$firewall->hasRole('admin'); // bool
$identity->hasRole('admin'); // bool
```

Although it's easy to set up roles-based authorization, it may backfire as the app gets more complicated. Usually in a
company not just single role has access to single action and relying on roles may lead to conditions
like `$firewall->hasRole('supervisor') || $firewall->hasRole('admin') || $firewall->hasRole('editor') || ...`. Instead,
we use [privilege-based authorization](#privileges).

### Privileges

Privilege is a right to commit an action.

Privileges are checked via `$firewall->isAllowed()` and `$authorizer->isAllowed()` methods.

There is also `$authorizer->hasPrivilege()` method, but it should not be used outside of policies because its purpose
is to bypass policy checks to prevent infinite loops (like `ArticleEditPolicy` calling `isAllowed('article.edit')`).

User privileges have two sources, combined into one during check:

- [role](#roles) privileges, assigned during [authorization setup](#authorization-setup)
- [identity](#identity) privileges, assigned to identity [directly](#identity-privileges)

Privileges are composed in a hierarchical structure, in which individual sub-privileges are separated by a dot.

- Adding privilege `article.edit.all` via `$builder->addPrivilege()`adds also privileges `article.edit` and `article`.
- Assigning privilege `article` to user gives them also all the sub-privileges - all these whose name starts
  with `article.`.
- Checking whether user has privilege `article` checks also all sub-privileges - user has to have all which start
  with `article.`.
	- Policy is checked **only for exact privilege**, not for sub-privileges nor parent privileges. That means
	  when `article.edit` has a policy and `isAllowed('article')` is called, the `article.edit` policy is not checked.
	- To check whether user has a privilege, all roles and identity privileges are combined. Having each sub-privilege
	  at least from one role or identity is enough to have the whole privilege.

#### Identity privileges

Each user can have their privileges assigned directly, without any roles.

```php
use Orisai\Auth\Authorization\AuthorizationDataBuilder;
use Orisai\Auth\Authorization\IdentityAuthorizationDataBuilder;
use Orisai\Auth\Authentication\IntIdentity;

$dataBuilder = new AuthorizationDataBuilder();
// ...
$data = $dataBuilder->build();

$identity = new IntIdentity($user->id, $user->roles);
$identityDataBuilder = new IdentityAuthorizationDataBuilder($data);

if ($user->root) {
	$identityDataBuilder->addRoot($identity);
}

foreach ($user->privileges as $privilege) {
	$identityDataBuilder->allow($identity, $privilege);
}

$identity->setAuthorizationData($identityDataBuilder->build($identity));
```

### Policies - customized authorization

Policy is a class used for custom implementation of privilege check, completely replacing default full privilege match.
It may request an object from `isAllowed()` call and services via constructor to perform any checks needed.

> `hasPrivilege()` checks only privilege, without calling policy

```php
$policyManager->add(new ArticleEditOwnedPolicy());
// ...
$authorizer->isAllowed($identity, 'article.edit.owned', $article); // bool
$firewall->isAllowed('article.edit.owned', $article); // bool
```

```php
use Generator;
use Orisai\Auth\Authorization\Authorizer;
use Orisai\Auth\Authentication\Identity;
use Orisai\Auth\Authorization\AccessEntry;
use Orisai\Auth\Authorization\AccessEntryResult;
use Orisai\Auth\Authorization\Policy;
use Orisai\Auth\Authorization\PolicyContext;

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
	public function isAllowed(Identity $identity, object $requirements, PolicyContext $context): Generator
	{
		$authorizer = $context->getAuthorizer();

		$res = $authorizer->hasPrivilege($identity, self::getPrivilege())
			&& $identity->getId() === $requirements->getAuthor()->getId();

		yield new AccessEntry(
			AccessEntryResult::fromBool($res),
			'',
		);
	}

}
```

Each policy has to be registered by `PolicyManager`:

```php
use Orisai\Auth\Authorization\SimplePolicyManager;

$policyManager = new SimplePolicyManager();
$policyManager->add(new ArticleEditPolicy());
$policyManager->add(new ArticleEditOwnedPolicy());
```

Alternative, lazy implementations available are in:

- [orisai/nette-auth](https://github.com/orisai/nette-auth) - for [nette/di](https://github.com/nette/di)

Requirements can be made [optional](#policy-with-optional-requirements) or even [none](#policy-with-no-requirements) at
all.

Policy is called only when user is logged-in. For logged-out
users, [make Identity optional](#policy-with-optional-log-in-check).

For privileges with registered policy, privilege itself **is not checked**. Policy has
to [do the check itself](#policy-with-default-like-privilege-check).

Policy is always skipped by [root](#root---bypass-all-checks).

#### Policy context

Policy provides a context to make authorizer calls to subsequent policies, access current users expired logins, ...:

```php
use Generator;
use Orisai\Auth\Authentication\Identity;
use Orisai\Auth\Authorization\AccessEntry;
use Orisai\Auth\Authorization\AccessEntryResult;
use Orisai\Auth\Authorization\Policy;
use Orisai\Auth\Authorization\PolicyContext;

final class ContextAwarePolicy implements Policy
{

	// ...

	public function isAllowed(Identity $identity, object $requirements, PolicyContext $context): Generator
	{
		$context->isCurrentUser(); // bool

		foreach ($context->getExpiredLogins() as $expiredLogin) {
			// ...
		}

		$authorizer = $context->getAuthorizer();

		$res = $authorizer->isAllowed('contextAware.subprivilege1')
			&& $authorizer->isAllowed('contextAware.subprivilege2');

		yield new AccessEntry(
			AccessEntryResult::fromBool($res),
			'',
		);
	}

}
```

#### Policy with optional log-in check

Only logged-in users are checked via policy, logged-out users are not allowed to do anything. If you want to authorize
also logged-out users, implement the `OptionalIdentityPolicy`.

```php
$firewall->isAllowed(OnlyLoggedOutUserPolicy::getPrivilege(), new stdClass());
$authorizer->isAllowed($identity, OnlyLoggedOutUserPolicy::getPrivilege(), new stdClass());
$authorizer->isAllowed(null, OnlyLoggedOutUserPolicy::getPrivilege(), new stdClass());
```

```php
use Generator;
use Orisai\Auth\Authentication\Identity;
use Orisai\Auth\Authorization\AccessEntry;
use Orisai\Auth\Authorization\AccessEntryResult;
use Orisai\Auth\Authorization\NoRequirements;
use Orisai\Auth\Authorization\OptionalRequirementsPolicy;
use Orisai\Auth\Authorization\PolicyContext;
use stdClass;

final class OnlyLoggedOutUserPolicy implements OptionalIdentityPolicy
{

	// ...

	public static function getRequirementsClass(): string
	{
		return stdClass::class;
	}

	public function isAllowed(?Identity $identity, object $requirements, PolicyContext $context): Generator
	{
		// Only logged-out user is allowed

		yield new AccessEntry(
			AccessEntryResult::fromBool($identity === null),
			'',
		);
	}

}
```

#### Policy with optional requirements

Requirements may be marked optional by implementing `OptionalRequirementsPolicy`. It allows requirements to be null:

```php
$firewall->isAllowed(OptionalRequirementsPolicy::getPrivilege());
$firewall->isAllowed(OptionalRequirementsPolicy::getPrivilege(), new stdClass());
$authorizer->isAllowed($identity, OptionalRequirementsPolicy::getPrivilege());
$authorizer->isAllowed($identity, OptionalRequirementsPolicy::getPrivilege(), new stdClass());
```

```php
use Generator;
use Orisai\Auth\Authentication\Identity;
use Orisai\Auth\Authorization\NoRequirements;
use Orisai\Auth\Authorization\OptionalRequirementsPolicy;
use Orisai\Auth\Authorization\PolicyContext;
use stdClass;

final class OptionalRequirementsPolicy implements OptionalRequirementsPolicy
{

	// ...

	public static function getRequirementsClass(): string
	{
		return stdClass::class;
	}

	public function isAllowed(Identity $identity, ?object $requirements, PolicyContext $context): Generator
	{
		if ($requirements === null) {
			// yield ...
		} else {
			// yield ...
		}
	}

}
```

#### Policy with no requirements

Policy which does not have any requirements may use `NoRequirements`. Authorizer will create this object for you so you
don't have to pass it via `isAllowed()`:

```php
$firewall->isAllowed(NoRequirementsPolicy::getPrivilege());
$authorizer->isAllowed($identity, NoRequirementsPolicy::getPrivilege());
```

```php
use Generator;
use Orisai\Auth\Authentication\Identity;
use Orisai\Auth\Authorization\AccessEntry;
use Orisai\Auth\Authorization\AccessEntryResult;
use Orisai\Auth\Authorization\NoRequirements;
use Orisai\Auth\Authorization\Policy;
use Orisai\Auth\Authorization\PolicyContext;

final class NoRequirementsPolicy implements Policy
{

	// ...

	public static function getRequirementsClass(): string
	{
		return NoRequirements::class;
	}

	/**
	 * @param NoRequirements $requirements
	 */
	public function isAllowed(Identity $identity, object $requirements, PolicyContext $context): Generator
	{
		yield new AccessEntry(
			AccessEntryResult::allowed(),
			'',
		);
	}

}
```

#### Policy with default-like privilege check

Setting a policy makes the privilege itself **optional and therefore not checked**. To fall back to default behavior,
check privilege via authorizer yourself:

```php
$firewall->isAllowed(DefaultCheckPolicy::getPrivilege());
$authorizer->isAllowed($identity, DefaultCheckPolicy::getPrivilege());
```

```php
use Generator;
use Orisai\Auth\Authentication\Identity;
use Orisai\Auth\Authorization\AccessEntry;
use Orisai\Auth\Authorization\AccessEntryResult;
use Orisai\Auth\Authorization\NoRequirements;
use Orisai\Auth\Authorization\Policy;
use Orisai\Auth\Authorization\PolicyContext;

final class DefaultCheckPolicy implements Policy
{

	// ...

	public static function getRequirementsClass(): string
	{
		return NoRequirements::class;
	}

	public function isAllowed(Identity $identity, object $requirements, PolicyContext $context): Generator
	{
		$authorizer = $context->getAuthorizer();

		yield new AccessEntry(
			AccessEntryResult::fromBool($authorizer->hasPrivilege($identity, self::getPrivilege())),
			'',
		);
	}

}
```

### Root - bypass all checks

Root privilege is a special privilege which bypasses both privilege and policy checks - neither of them is called,
everything is accessible by root.

```php
$builder->addRoot('groot');
// ...
$firewall->login(new IntIdentity(123, ['groot']));
$firewall->isAllowed('anything'); // true
$firewall->isRoot(); // true
```

### Check authorization of not current user

User does not have to be logged into firewall in order to check their permissions. Just create an identity for the user
and use authorizer instead of firewall:

```php
$authorizer->isAllowed($identity, 'privilege.name');
```

We may also access authorizer used in firewall. This is useful for verifying user permissions before logging in:

```php
$firewall = $this->getFirewall();
if (!$firewall->getAuthorizer()->isAllowed($identity, 'administration.entry')) {
	// Not an admin
	return;
}

$firewall->login($identity);
```

### Access entries

Reasons why user has or does not have permission can be described by a policy by adding access entries:

```php
use Generator;
use Orisai\Auth\Authentication\Identity;
use Orisai\Auth\Authorization\AccessEntry;
use Orisai\Auth\Authorization\AccessEntryResult;
use Orisai\Auth\Authorization\Policy;
use Orisai\Auth\Authorization\PolicyContext;

final class WillTellYouWhyPolicy implements Policy
{

	// ...

	public function isAllowed(Identity $identity, object $requirements, PolicyContext $context): Generator
	{
		yield new AccessEntry(
			AccessEntryResult::fromBool(/* true|false */),
			'access requirement',
		);
	}

}
```

Both authorizer and firewall return access entry via reference:

```php
use Orisai\TranslationContracts\Translatable;
use Orisai\TranslationContracts\Translator;

assert($translator instanceof Translator); // Create translator or get message id and parameters from Translatable

$firewall->isAllowed(DefaultCheckPolicy::getPrivilege(), $requirements, $entry);
$authorizer->isAllowed($identity, DefaultCheckPolicy::getPrivilege(), $requirements, $entry);

if ($entry !== null) {
	$message = $entry->getMessage();
	if ($message instanceof Translatable) {
		$message = $translator->translateMessage($message);
	}
}
```

### Access authorization data

Access authorization data from authorizer

```php
$data = $authorizer->getData(); // AuthorizationData

$data->getRoles(); // array<int, string>
$data->getPrivileges(); // array<int, string>
$data->getRootRoles(); // array<int, string>
$data->getAllowedPrivilegesForRole('role'); // array<int, string>
$data->privilegeExists('privilege.name'); // bool
```

## Passwords

Hash and verify passwords.

```php
use Example\Core\User\User;
use Example\Front\Auth\FrontFirewall;
use Orisai\Auth\Authentication\IntIdentity;
use Orisai\Auth\Passwords\PasswordHasher;

final class UserLogin
{

	private PasswordHasher $passwordHasher;

	private FrontFirewall $frontFirewall;

	public function __construct(PasswordHasher $passwordHasher, FrontFirewall $frontFirewall)
	{
		$this->passwordHasher = $passwordHasher;
		$this->frontFirewall = $frontFirewall;
	}

	public function login(string $email, string $password): void
	{
		$user; // Query user from database by $email

		if ($this->passwordHasher->isValid($password, $user->password)) {
			$this->updateHashedPassword($user, $password);

			// Login user
			$this->frontFirewall->login(new IntIdentity($user->id, $user->roles));
		}
	}

	public function register(string $password): void
	{
		$hashedPassword = $this->passwordHasher->hash($password);

		// Register user
	}

	private function updateHashedPassword(User $user, string $password): void
	{
		if (!$this->passwordHasher->needsRehash($user->password)) {
			return;
		}

		$user->password = $this->passwordHasher->hash($password);
		// Persist user to database
	}

}
```

Make sure your password storage allows at least 255 characters. Each algorithm produces hashed strings of different
length and even different settings of an algorithm may vary in results.

All hashes produced by this library follow
[PHC string format](https://github.com/P-H-C/phc-string-format/blob/master/phc-sf-spec.md)

### Argon2 hasher

Hash passwords with **argon2id** algorithm. This hasher is **recommended**.

```php
use Orisai\Auth\Passwords\Argon2PasswordHasher;

$hasher = new Argon2PasswordHasher();
```

Options:

> Don't set any options on lower than default unless it's configuration for tests. Lower values may make algorithm usage
> not secure enough.

- `Argon2PasswordHasher(?int $timeCost, ?int $memoryCost, ?int $threads)`
    - `$timeCost`
        - Maximum amount of time it may take to compute the hash
        - Increase to make computing of hash harder (more secure, but longer and more CPU intensive)
        - Default: `16`
    - `$memoryCost`
        - Maximum memory that may be used to compute the hash
        - Increase to make hash computing consume more memory (be aware using more memory increases computation time)
        - Defined in KiB (kibibytes)
        - Default: `65_535`
    - `$threads`
      - Number of threads to use for computing the hash
      - Increase to make computing of hash faster without making it less secure
      - default: `4`

### Bcrypt hasher

Hash passwords with **bcrypt** algorithm. Unless sodium php extension is not available on your setup then always
prefer [argon2 hasher](#argon2-hasher).

*Note:* bcrypt algorithm trims password before hashing to 72 characters. You should not worry about it because it does
not have any usage impact, but it may cause issues if you are migrating from a bcrypt-hasher which modified password to
be 72 characters or fewer before hashing, so please ensure produced hashes are considered valid by password hasher.

```php
use Orisai\Auth\Passwords\BcryptPasswordHasher;

$hasher = new BcryptPasswordHasher();
```

Options:

> Don't set any options on lower than default unless it's configuration for tests. Lower values may make algorithm usage
> not secure enough.

- `BcryptPasswordHasher(int $cost)`
	- `$cost`
		- Cost of the algorithm
		- Must be in range `4-31`
		- Default: `13`

### Backward compatibility - upgrading when user logs in

> Following approach is suitable only if we are migrating from secure settings of a secure algorithm. For upgrade from
> an unsecure algorithm, check
> [migrating from an unsafe algorithm](#backward-compatibility---migrating-from-an-unsafe-algorithm).

If you are migrating to new algorithm, use `UpgradingPasswordHasher`. It requires a preferred hasher and optionally
accepts fallback hashers.

If you migrate from a `password_verify()`-compatible password validation method then you don't need any fallback
hashers as it is done automatically for you. These passwords should always start with string like `$2a$`, `$2x$`,
`$argon2id$` etc.

If you need fallback to a *custom hasher*, implement an `Orisai\Auth\Passwords\PasswordHasher`.

```php
use Orisai\Auth\Passwords\Argon2PasswordHasher;
use Orisai\Auth\Passwords\UpgradingPasswordHasher;

// With only preferred hasher
$hasher = new UpgradingPasswordHasher(
    new Argon2PasswordHasher()
);

// With outdated fallback hashers
$hasher = new UpgradingPasswordHasher(
    new Argon2PasswordHasher(),
    [
        new ExamplePasswordHasher(),
    ]
);
```

### Backward compatibility - migrating from an unsafe algorithm

When we have an unsafe hashing algorithm like md5, sha-* or even safer one but with low settings, we should not wait
with rehash on user logging in.

Instead, use the existing password hashes as inputs for a more secure algorithm. For example, if the application
originally stored passwords as `md5($password)`, this could be easily upgraded to `bcrypt(md5($password))`. Layering the
hashes avoids the need to know the original password; however, it can make the hashes easier to crack. These hashes
should be replaced with direct hashes of the users' passwords next time the user logs in.
