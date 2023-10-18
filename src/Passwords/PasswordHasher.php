<?php declare(strict_types = 1);

namespace Orisai\Auth\Passwords;

use SensitiveParameter;

interface PasswordHasher
{

	 // phpcs:ignore SlevomatCodingStandard.Classes.RequireSingleLineMethodSignature
	public function hash(
		#[SensitiveParameter]
		string $raw
	): string;

	public function needsRehash(string $hashed): bool;

	public function isValid(
		#[SensitiveParameter]
		string $raw,
		string $hashed
	): bool;

}
