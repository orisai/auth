# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](http://keepachangelog.com/en/1.0.0/)
and this project adheres to [Semantic Versioning](http://semver.org/spec/v2.0.0.html).

## [Unreleased](https://github.com/orisai/auth/compare/1.0.4...v1.x)

## [1.0.4](https://github.com/orisai/auth/compare/1.0.3...1.0.4) - 2022-12-09

- Composer
  - fix minimal version of orisai/clock
  - allows PHP 8.2

## [1.0.3](https://github.com/orisai/auth/compare/1.0.2...1.0.3) - 2022-11-25

### Added

- `BaseFirewall`
  - accepts `Psr\Clock\ClockInterface` instead of `Orisai\Clock\Clock` (backward compatible)

## [1.0.2](https://github.com/orisai/auth/compare/1.0.1...1.0.2) - 2022-11-03

### Added

- `Firewall` and `Authorizer`
  - `isAllowed()` parameter `decision` has correct return type for referenced variable

### Changed

- `LogoutCode`
	- cases names are PascalCase (matches future enum behavior)

## [1.0.1](https://github.com/orisai/auth/compare/1.0.0...1.0.1) - 2022-10-14

### Changed

- `LogoutCode`
  - cases reuse existing object instance (matches native enum behavior)

## [1.0.0](https://github.com/orisai/auth/releases/tag/1.0.0) - 2022-08-19

### Added

Authentication

- `Firewall` interface
	- abstract `BaseFirewall`
	- `SimpleFirewall`
	- current login, expired logins
- `Identity` interface
	- abstract `BaseIdentity`
	- `IntIdentity`
	- `StringIdentity`
- `LoginStorage` interface
	- `ArrayLoginStorage`
- `IdentityRefresher` interface
	- `IdentityExpired` exception with `DecisionReason` support

Authorization

- `Authorizer` interface
	- `PrivilegeAuthorizer`
	- roles, role privileges, identity privileges, policies, root, current/any user check
- `Policy` interface
	- `OptionalIdentityPolicy`
	- `OptionalRequirementsPolicy`
	- `NoRequirements`
	- `DecisionReason`
	- `PolicyContext`
	- `PolicyManager` interface
		- `SimplePolicyManager`

Passwords

- `PasswordHasher` interface
	- `ArgonPasswordHasher`
	- `BcryptPasswordHasher`
	- `UpgradingPasswordHasher`
