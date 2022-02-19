# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](http://keepachangelog.com/en/1.0.0/)
and this project adheres to [Semantic Versioning](http://semver.org/spec/v2.0.0.html).

## [Unreleased](https://github.com/orisai/auth/compare/...HEAD)

### Added

Passwords
- `PasswordEncoder` interface
    - `BcryptPasswordEncoder`
    - `SodiumPasswordEncoder`
    - `UnsafeMD5PasswordEncoder`
    - `UpgradingPasswordEncoder`

Authentication
- `Firewall` interface
    - `BaseFirewall`
- `Identity` interface
    - `IntIdentity`
    - `StringIdentity`
- `LoginStorage` interface
    - `ArrayLoginStorage`
- `IdentityRenewer` interface

Authorization
- `Authorizer` interface
	- `PermissionAuthorizer`
- `Policy` interface
	- `PolicyManager` interface
	- `SimplePolicyManager`
- `NoRequirements` Policy requirement

Bridges
- Nette
	- `SessionLoginStorage`
	- `LazyPolicyManager`
