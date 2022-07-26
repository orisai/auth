<?php declare(strict_types = 1);

namespace Tests\Orisai\Auth\Unit\Authorization;

use Orisai\Auth\Authorization\AuthorizationDataBuilder;
use Orisai\Auth\Authorization\SimpleAuthorizationDataCreator;
use PHPUnit\Framework\TestCase;

final class SimpleAuthorizationDataCreatorTest extends TestCase
{

	public function test(): void
	{
		$builder = new AuthorizationDataBuilder();
		$builder->addPrivilege('p');
		$builder->addRole('r');
		$builder->allow('r', 'p');

		$creator = new SimpleAuthorizationDataCreator($builder);
		self::assertEquals($builder->build(), $creator->create());
	}

}
