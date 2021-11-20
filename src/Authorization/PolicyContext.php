<?php declare(strict_types = 1);

namespace Orisai\Auth\Authorization;

interface PolicyContext
{

	public function getAuthorizer(): Authorizer;

}
