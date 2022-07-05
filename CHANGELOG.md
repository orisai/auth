# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](http://keepachangelog.com/en/1.0.0/)
and this project adheres to [Semantic Versioning](http://semver.org/spec/v2.0.0.html).

## [Unreleased](https://github.com/orisai/auth/compare/...HEAD)

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
