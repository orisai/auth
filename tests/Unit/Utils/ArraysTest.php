<?php declare(strict_types = 1);

namespace Tests\Orisai\Auth\Unit\Utils;

use Generator;
use Orisai\Auth\Utils\Arrays;
use PHPUnit\Framework\TestCase;

final class ArraysTest extends TestCase
{

	public function testKeysToStrings(): void
	{
		$array = [
			'article' => [
				'view' => [],
				'edit' => [
					'all' => '123',
					'owned' => 123,
				],
			],
			'a' => [
				'b' => null,
			],
			'c' => null,
			0 => true,
			6 => false,
		];

		self::assertSame(
			[
				'article.view',
				'article.edit.all',
				'article.edit.owned',
				'a.b',
				'c',
				'0',
				'6',
			],
			Arrays::keysToStrings($array),
		);
	}

	/**
	 * @param non-empty-array<string> $keys
	 * @param array<mixed>            $array
	 * @param array<mixed>|null       $expected
	 *
	 * @dataProvider getKeyProvider
	 */
	public function testGetKey(array $keys, array $array, ?array $expected): void
	{
		self::assertSame(
			$expected,
			Arrays::getKey($array, $keys),
		);
	}

	/**
	 * @return Generator<array<mixed>>
	 */
	public function getKeyProvider(): Generator
	{
		yield [
			['app', 'article'],
			[
				'app' => [
					'article' => [
						'view' => [],
						'edit' => [],
					],
				],
			],
			[
				'view' => [],
				'edit' => [],
			],
		];

		yield [
			['app', 'article', 'create'],
			[
				'app' => [
					'article' => [
						'view' => [],
						'edit' => [],
					],
				],
			],
			null,
		];
	}

}
