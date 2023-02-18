<?php declare(strict_types = 1);

namespace Orisai\Auth\Authorization;

/**
 * @internal
 */
abstract class BaseUserPolicyContext implements PolicyContext
{

	private Authorizer $authorizer;

	private ?AccessEntry $accessEntry = null;

	public function __construct(Authorizer $authorizer)
	{
		$this->authorizer = $authorizer;
	}

	public function getAuthorizer(): Authorizer
	{
		return $this->authorizer;
	}

	public function setAccessEntry(AccessEntry $entry): void
	{
		$this->accessEntry = $entry;
	}

	public function getAccessEntry(): ?AccessEntry
	{
		return $this->accessEntry;
	}

}
