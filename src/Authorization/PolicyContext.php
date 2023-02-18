<?php declare(strict_types = 1);

namespace Orisai\Auth\Authorization;

use Orisai\Auth\Authentication\Data\ExpiredLogin;

interface PolicyContext
{

	public function isCurrentUser(): bool;

	public function getAuthorizer(): Authorizer;

	public function addAccessEntry(AccessEntry $entry): void;

	/**
	 * @return list<AccessEntry>
	 */
	public function getAccessEntries(): array;

	/**
	 * @return array<ExpiredLogin>
	 */
	public function getExpiredLogins(): array;

}
