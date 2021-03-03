<?php declare(strict_types = 1);

namespace Tests\Orisai\Auth\Unit\Authorization;

use Generator;
use Orisai\Auth\Authorization\PrivilegeProcessor;
use Orisai\Exceptions\Logic\InvalidArgument;
use PHPUnit\Framework\TestCase;

final class PrivilegeProcessorTest extends TestCase
{

	/**
	 * @dataProvider privilegeParsingProvider
	 */
	public function testPrivilegeParsing(string $privilege, string $message): void
	{
		$this->expectException(InvalidArgument::class);
		$this->expectExceptionMessage($message);

		PrivilegeProcessor::parsePrivilege($privilege);
	}

	/**
	 * @return Generator<array<mixed>>
	 */
	public function privilegeParsingProvider(): Generator
	{
		yield [
			'',
			'Privilege is an empty string, which is not allowed.',
		];

		yield [
			'article.*',
			'Privilege article.* contains `*`, which can be used only standalone.',
		];

		yield [
			'.article',
			'Privilege .article starts with dot `.`, which is not allowed.',
		];

		yield [
			'article.',
			'Privilege article. ends with dot `.`, which is not allowed.',
		];

		yield [
			'article..view',
			'Privilege article..view contains multiple adjacent dots, which is not allowed.',
		];
	}

}
