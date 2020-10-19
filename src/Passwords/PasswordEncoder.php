<?php declare(strict_types = 1);

namespace Orisai\Auth\Passwords;

interface PasswordEncoder
{

	public function encode(string $raw): string;

	public function needsReEncode(string $encoded): bool;

	public function isValid(string $raw, string $encoded): bool;

}
