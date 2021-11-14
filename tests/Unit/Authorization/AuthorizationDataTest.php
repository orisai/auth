<?php declare(strict_types = 1);

namespace Tests\Orisai\Auth\Unit\Authorization;

use Orisai\Auth\Authorization\AuthorizationData;
use PHPUnit\Framework\TestCase;

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
	}

}
