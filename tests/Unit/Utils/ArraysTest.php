<?php declare(strict_types = 1);

namespace Tests\Orisai\Auth\Unit\Utils;

use Orisai\Auth\Utils\Arrays;
use PHPUnit\Framework\TestCase;

final class ArraysTest extends TestCase
{

	public function test(): void
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

}
