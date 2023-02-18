<?php declare(strict_types = 1);

namespace Orisai\Auth\Authorization;

/**
 * @internal
 */
abstract class BaseUserPolicyContext implements PolicyContext
{

	private Authorizer $authorizer;

	/** @var list<AccessEntry> */
	private array $accessEntries = [];

	public function __construct(Authorizer $authorizer)
	{
		$this->authorizer = $authorizer;
	}

	public function getAuthorizer(): Authorizer
	{
		return $this->authorizer;
	}

	public function addAccessEntry(AccessEntry $entry): void
	{
		$this->accessEntries[] = $entry;
	}

	public function getAccessEntries(): array
	{
		return $this->accessEntries;
	}

}
