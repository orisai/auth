# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](http://keepachangelog.com/en/1.0.0/)
and this project adheres to [Semantic Versioning](http://semver.org/spec/v2.0.0.html).

## [Unreleased](https://github.com/orisai/auth/compare/2.0.1...v2.x)

### Changed

- Requires `orisai/clock:^1.2.0`

## [2.0.1](https://github.com/orisai/auth/compare/2.0.0...2.0.1) - 2023-10-18

### Changed

- Password hashers - redact passwords

## [2.0.0](https://github.com/orisai/auth/compare/1.0.4...2.0.0) - 2023-03-01

### Added

- `AccessEntry` - represents a single check in a policy
	- `getType(): AccessEntryResult` - result of the check
	- `getMessage(): string|Translatable` - text description of what was checked
	- `matchAny(): MatchAnyOfEntries`, `matchAll(): MatchAllOfEntries` shortcuts to construct && and || conditions
	- `forRequiredPrivilege()` shortcut for (translated) required privilege entry
- `AccessEntryResult`
	- `allowed()`, `forbidden()`, `skipped()`
	- `fromBool()` - shortcut for `allowed()` or `forbidden()`
- `MatchAllOfEntries` - for explicit && condition (implicit is default)
- `MatchAnyOfEntries` - for || condition
- `PolicyContext`
	- `getLastExpiredLogin()`

### Changed

- `Policy`
  - uses `AccessEntry` instead of `DecisionReason` (also replaced in `Firewall` and `Authorizer` `isAllowed()` methods)
  - allows to add multiple `AccessEntry` (`Firewall` and `Authorizer` `isAllowed()` methods return an array)
	- instead of returning `bool` uses `Generator` which yields 1 or more `AccessEntry|MatchAllOfEntries|MatchAnyOfEntries`
	- `DecisionReason` removed from context (uses `AccessEntry` yielding instead)
- `Firewall`, `Authorizer`
	- `isAllowed()` reason (`DecisionReason`) replaced by entries (`list<AccessEntry|MatchAllOfEntries|MatchAnyOfEntries>`)
- `Authorizer`
	- adds an entry for privilege when no policy is used
- `IdentityExpired`
	- `create()` uses `string|TranslatableMessage` directly instead of `DecisionReason`
- `ExpiredLogin`
	- `getLogoutReason()` returns `string|TranslatableMessage` directly instead of `DecisionReason`
- root has exact same `hasPrivilege()` and `isAllowed()` checks as other users
	- but always returns true (behavior remains unchanged)
	- policies are executed to ensure their validity
	- access entries are returned for root (to verify which entries would fail or be skipped without root)
- more accurate typehints (mostly changed `array` to `list`)

### Removed

- `DecisionReason`
	- replaced by `string|Translatable`
