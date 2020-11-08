# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](http://keepachangelog.com/en/1.0.0/)
and this project adheres to [Semantic Versioning](http://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

Passwords
- `PasswordEncoder` interface
    - `BcryptPasswordEncoder`
    - `SodiumPasswordEncoder`
    - `UpgradingPasswordEncoder`
Authentication
- `Firewall` interface
    - `BaseFirewall`
- `Identity` interface
    - `IntIdentity`
    - `StringIdentity`
- `IdentityStorage` interface
    - `NetteSessionIdentityStorage`
- `IdentityRenewer` interface

[Unreleased]: https://github.com/orisai/auth/compare/...HEAD