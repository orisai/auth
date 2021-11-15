<?php declare(strict_types = 1);

namespace Tests\Orisai\Auth\Unit\Authorization;

use Orisai\Auth\Authorization\IdentityAuthorizationData;
use PHPUnit\Framework\TestCase;
use function serialize;
use function unserialize;

final class IdentityAuthorizationDataTest extends TestCase
{

	public function test(): void
	{
		$data = new IdentityAuthorizationData(
			$id = 1,
			$allowedPrivileges = [
				'article' => [
					'view' => [],
					'edit' => [],
				],
			],
		);

		self::assertSame($id, $data->getId());
		self::assertSame($allowedPrivileges, $data->getRawAllowedPrivileges());
		self::assertSame(
			['article.view', 'article.edit'],
			$data->getAllowedPrivileges(),
		);

		self::assertEquals($data, unserialize(serialize($data)));
	}

	public function testSerializationBC(): void
	{
		// phpcs:ignore SlevomatCodingStandard.Files.LineLength.LineTooLong
		$serialized = 'O:51:"Orisai\Auth\Authorization\IdentityAuthorizationData":2:{s:2:"id";i:1;s:20:"rawAllowedPrivileges";a:0:{}}';
		$data = unserialize($serialized);

		self::assertInstanceOf(IdentityAuthorizationData::class, $data);
		self::assertSame(1, $data->getId());
		self::assertSame([], $data->getRawAllowedPrivileges());
	}

}
