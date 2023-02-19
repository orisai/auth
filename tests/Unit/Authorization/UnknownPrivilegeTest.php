<?php declare(strict_types = 1);

namespace Tests\Orisai\Auth\Unit\Authorization;

use Orisai\Auth\Authorization\Exception\UnknownPrivilege;
use PHPUnit\Framework\TestCase;
use stdClass;

final class UnknownPrivilegeTest extends TestCase
{

	public function test(): void
	{
		$e = UnknownPrivilege::forFunction('article.edit', stdClass::class, 'function');

		self::assertSame(
			<<<'MSG'
Context: Calling stdClass->function().
Problem: Privilege 'article.edit' is unknown.
Solution: Add privilege to data builder first via addPrivilege().
MSG,
			$e->getMessage(),
		);
		self::assertSame('article.edit', $e->getPrivilege());
	}

}
