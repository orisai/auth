# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](http://keepachangelog.com/en/1.0.0/)
and this project adheres to [Semantic Versioning](http://semver.org/spec/v2.0.0.html).

## [Unreleased](https://github.com/orisai/auth/compare/1.0.4...v2.x)

### Added

- `AccessEntry` - represents a single check in a policy
	- `getType(): AccessEntryResult` - result of the check
	- `getMessage(): string|Translatable` - text description of what was checked
- `AccessEntryResult`
	- `allowed()`, `forbidden()`, `skipped()`
	- `fromBool()` - shortcut for `allowed()` or `forbidden()`
- `PolicyContext`
	- `getLastExpiredLogin()`

### Changed

- `Policy`
  - uses `AccessEntry` instead of `DecisionReason` (also replaced in `Firewall` and `Authorizer` `isAllowed()` methods)
  - allows to add multiple `AccessEntry` (`Firewall` and `Authorizer` `isAllowed()` methods return an array)
	- instead of returning `bool` uses `Generator` which yields 1 or more `AccessEntry`
	- `DecisionReason` removed from context (uses `AccessEntry` yielding instead)
- `Firewall`, `Authorizer`
	- `isAllowed()` reason (`DecisionReason`) replaced by entries (`list<AccessEntry>`)
- `IdentityExpired`
	- `create()` uses `string|TranslatableMessage` directly instead of `DecisionReason`
- `ExpiredLogin`
	- `getLogoutReason()` returns `string|TranslatableMessage` directly instead of `DecisionReason`
- root has exact same `hasPrivilege()` and `isAllowed()` checks as other users
	- but always returns true (behavior remains unchanged)
	- policies are executed to ensure their validity
	- access entries are returned for root (to verify which entries would fail or be skipped without root)

### Removed

- `DecisionReason`
	- replaced by `string|Translatable`
