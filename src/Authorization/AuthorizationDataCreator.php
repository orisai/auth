<?php declare(strict_types = 1);

namespace Orisai\Auth\Authorization;

interface AuthorizationDataCreator
{

	public function create(): AuthorizationData;

}
