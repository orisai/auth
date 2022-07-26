<?php declare(strict_types = 1);

namespace Orisai\Auth\Authorization;

final class SimpleAuthorizationDataCreator implements AuthorizationDataCreator
{

	private AuthorizationDataBuilder $builder;

	public function __construct(AuthorizationDataBuilder $builder)
	{
		$this->builder = $builder;
	}

	public function create(): AuthorizationData
	{
		return $this->builder->build();
	}

}
