<?php declare(strict_types = 1);

namespace Orisai\Auth\Passwords;

interface PasswordHasher
{

	public function hash(string $raw): string;

	public function needsRehash(string $hashed): bool;

	public function isValid(string $raw, string $hashed): bool;

}
