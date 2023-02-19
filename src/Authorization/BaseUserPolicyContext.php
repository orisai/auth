<?php declare(strict_types = 1);

namespace Orisai\Auth\Authorization;

/**
 * @readonly
 *
 * @internal
 */
abstract class BaseUserPolicyContext implements PolicyContext
{

	private Authorizer $authorizer;

	public function __construct(Authorizer $authorizer)
	{
		$this->authorizer = $authorizer;
	}

	public function getAuthorizer(): Authorizer
	{
		return $this->authorizer;
	}

}
