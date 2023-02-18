<?php declare(strict_types = 1);

namespace Orisai\Auth\Authorization;

use Orisai\Auth\Authentication\Data\ExpiredLogin;

interface PolicyContext
{

	public function isCurrentUser(): bool;

	public function getAuthorizer(): Authorizer;

	public function setAccessEntry(AccessEntry $entry): void;

	public function getAccessEntry(): ?AccessEntry;

	/**
	 * @return array<ExpiredLogin>
	 */
	public function getExpiredLogins(): array;

}
