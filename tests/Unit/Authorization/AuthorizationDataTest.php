<?php declare(strict_types = 1);

namespace Tests\Orisai\Auth\Unit\Authorization;

use Orisai\Auth\Authorization\AuthorizationData;
use PHPUnit\Framework\TestCase;
use function serialize;
use function unserialize;

final class AuthorizationDataTest extends TestCase
{

	public function test(): void
	{
		$data = new AuthorizationData(
			$roles = ['editor' => null],
			$privileges = [
				'article' => [
					'view' => [],
					'edit' => [],
					'delete' => [],
				],
			],
			$roleAllowedPrivileges = [
				'editor' => [
					'article' => [
						'view' => [],
						'edit' => [],
					],
				],
			],
			false,
		);

		self::assertFalse($data->isThrowOnUnknownPrivilege());

		self::assertSame($roles, $data->getRawRoles());
		self::assertSame(
			['editor'],
			$data->getRoles(),
		);

		self::assertSame($privileges, $data->getRawPrivileges());
		self::assertSame(
			['article.view', 'article.edit', 'article.delete'],
			$data->getPrivileges(),
		);
		self::assertTrue($data->privilegeExists('article.view'));
		self::assertTrue($data->privilegeExists('article.edit'));
		self::assertTrue($data->privilegeExists('article.delete'));
		self::assertTrue($data->privilegeExists('article'));
		self::assertFalse($data->privilegeExists('article.unknown'));
		self::assertFalse($data->privilegeExists('unknown'));

		self::assertSame($roleAllowedPrivileges, $data->getRawRoleAllowedPrivileges());
		self::assertSame(
			['article.view', 'article.edit'],
			$data->getAllowedPrivilegesForRole('editor'),
		);
		self::assertSame(
			[],
			$data->getAllowedPrivilegesForRole('unknown'),
		);

		self::assertEquals($data, unserialize(serialize($data)));
	}

	public function testSerializationBC(): void
	{
		// phpcs:ignore SlevomatCodingStandard.Files.LineLength.LineTooLong
		$serialized = 'O:43:"Orisai\Auth\Authorization\AuthorizationData":4:{s:8:"rawRoles";a:0:{}s:13:"rawPrivileges";a:0:{}s:24:"rawRoleAllowedPrivileges";a:0:{}s:23:"throwOnUnknownPrivilege";b:0;}';
		$data = unserialize($serialized);

		self::assertInstanceOf(AuthorizationData::class, $data);
		self::assertSame([], $data->getRawRoles());
		self::assertSame([], $data->getRawPrivileges());
		self::assertSame([], $data->getRawRoleAllowedPrivileges());
		self::assertFalse($data->isThrowOnUnknownPrivilege());
	}

}
