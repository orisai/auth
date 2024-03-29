<?php declare(strict_types = 1);

namespace Tests\Orisai\Auth\Unit\Authorization;

use Orisai\Auth\Authorization\AuthorizationDataBuilder;
use Orisai\Auth\Authorization\Exception\UnknownPrivilege;
use Orisai\Exceptions\Logic\InvalidState;
use PHPUnit\Framework\TestCase;
use Throwable;

final class AuthorizationDataBuilderTest extends TestCase
{

	public function testPrivileges(): void
	{
		$builder = new AuthorizationDataBuilder();

		$builder->addPrivilege('article');
		$builder->addPrivilege('article.view');
		$builder->addPrivilege('article.edit.owned');
		$builder->addPrivilege('article.edit.all');
		$builder->addPrivilege('article.edit');
		$builder->addPrivilege('account.create');

		$data = $builder->build();

		self::assertSame(
			[
				'article' => [
					'view' => [],
					'edit' => [
						'owned' => [],
						'all' => [],
					],
				],
				'account' => [
					'create' => [],
				],
			],
			$data->getRawPrivileges(),
		);

		self::assertSame(
			[
				'article.view',
				'article.edit.owned',
				'article.edit.all',
				'account.create',
			],
			$data->getPrivileges(),
		);
	}

	public function testPrivilegeExists(): void
	{
		$builder = new AuthorizationDataBuilder();
		$data = $builder->build();
		self::assertFalse($data->privilegeExists('article'));
		self::assertFalse($data->privilegeExists('article.edit'));
		self::assertFalse($data->privilegeExists('article.edit.all'));

		$builder->addPrivilege('article');
		$data = $builder->build();
		self::assertTrue($data->privilegeExists('article'));
		self::assertFalse($data->privilegeExists('article.edit'));
		self::assertFalse($data->privilegeExists('article.edit.all'));

		$builder->addPrivilege('article.edit.all');
		$data = $builder->build();
		self::assertTrue($data->privilegeExists('article'));
		self::assertTrue($data->privilegeExists('article.edit'));
		self::assertTrue($data->privilegeExists('article.edit.all'));
	}

	public function testRoles(): void
	{
		$builder = new AuthorizationDataBuilder();

		$builder->addRole('supervisor');
		$builder->addRole('admin');
		$builder->addRole('guest');
		$builder->addRole('supervisor');
		$builder->addRole('guest');

		$data = $builder->build();

		self::assertSame(
			[
				'supervisor',
				'admin',
				'guest',
			],
			$data->getRoles(),
		);
	}

	public function testRolesDataSeparated(): void
	{
		$builder = new AuthorizationDataBuilder();

		$builder->addPrivilege('article.view');
		$builder->addPrivilege('article.edit');
		$builder->addPrivilege('article.delete');
		$builder->addPrivilege('something');

		$role = 'editor';
		$role2 = 'another-role';
		$builder->addRole($role);
		$builder->addRole($role2);
		$data = $builder->build();

		self::assertSame(
			[
				'editor' => [],
				'another-role' => [],
			],
			$data->getRawRoleAllowedPrivileges(),
		);

		$builder->allow($role, 'article.view');
		$builder->allow($role, 'article.edit');
		$builder->allow($role2, 'article.delete');
		$data = $builder->build();
		self::assertSame(
			[
				'editor' => [
					'article' => [
						'view' => [],
						'edit' => [],
					],
				],
				'another-role' => [
					'article' => [
						'delete' => [],
					],
				],
			],
			$data->getRawRoleAllowedPrivileges(),
		);
	}

	public function testRoot(): void
	{
		$builder = new AuthorizationDataBuilder();

		$builder->addRole('a');
		$builder->addRole('b');

		$builder->addRoot('a');
		$builder->addRoot('b');
		$builder->removeRoot('b');

		$data = $builder->build();
		self::assertSame(
			['a' => null],
			$data->getRawRootRoles(),
		);
	}

	public function testAllowDenyA(): void
	{
		$builder = new AuthorizationDataBuilder();

		$builder->addPrivilege('article.view');
		$builder->addPrivilege('article.edit');
		$builder->addPrivilege('something');

		$role = 'editor';
		$builder->addRole($role);

		$builder->allow($role, 'article.view');
		$data = $builder->build();

		self::assertSame(
			[
				'editor' => [
					'article' => [
						'view' => [],
					],
				],
			],
			$data->getRawRoleAllowedPrivileges(),
		);

		$builder->removeAllow($role, 'article.view');
		$data = $builder->build();

		self::assertSame(
			[
				'editor' => [],
			],
			$data->getRawRoleAllowedPrivileges(),
		);
	}

	public function testAllowDenyB(): void
	{
		$builder = new AuthorizationDataBuilder();

		$builder->addPrivilege('article.view');
		$builder->addPrivilege('article.edit');
		$builder->addPrivilege('something');

		$role = 'editor';
		$builder->addRole($role);

		$builder->allow($role, 'article.view');
		$builder->allow($role, 'article.edit');
		$data = $builder->build();

		self::assertSame(
			[
				'editor' => [
					'article' => [
						'view' => [],
						'edit' => [],
					],
				],
			],
			$data->getRawRoleAllowedPrivileges(),
		);

		$builder->removeAllow($role, 'article.view');
		$data = $builder->build();

		self::assertSame(
			[
				'editor' => [
					'article' => [
						'edit' => [],
					],
				],
			],
			$data->getRawRoleAllowedPrivileges(),
		);
	}

	public function testAllowDenyC(): void
	{
		$builder = new AuthorizationDataBuilder();

		$builder->addPrivilege('article.view');
		$builder->addPrivilege('article.edit');
		$builder->addPrivilege('something');

		$role = 'editor';
		$builder->addRole($role);

		$builder->allow($role, 'article');
		$data = $builder->build();

		self::assertSame(
			[
				'editor' => [
					'article' => [
						'view' => [],
						'edit' => [],
					],
				],
			],
			$data->getRawRoleAllowedPrivileges(),
		);

		$builder->removeAllow($role, 'article');
		$data = $builder->build();

		self::assertSame(
			[
				'editor' => [],
			],
			$data->getRawRoleAllowedPrivileges(),
		);
	}

	public function testRolesPrivilegesNotOverridden(): void
	{
		$builder = new AuthorizationDataBuilder();

		$builder->addRole('role');
		$builder->addPrivilege('privilege');
		$builder->allow('role', 'privilege');
		$data = $builder->build();

		$rolePrivilegesData = $data->getRawRoleAllowedPrivileges();
		self::assertSame(
			[
				'role' => [
					'privilege' => [],
				],
			],
			$rolePrivilegesData,
		);

		$builder->addRole('role');
		$data = $builder->build();
		self::assertSame(
			$rolePrivilegesData,
			$data->getRawRoleAllowedPrivileges(),
		);
	}

	public function testAllowChecksRole(): void
	{
		$builder = new AuthorizationDataBuilder();

		$this->expectException(InvalidState::class);
		$this->expectExceptionMessage(
			'Role role does not exist, add it with Orisai\Auth\Authorization\AuthorizationDataBuilder->addRole($role)',
		);

		$builder->allow('role', 'article');
	}

	public function testDenyChecksRole(): void
	{
		$builder = new AuthorizationDataBuilder();

		$this->expectException(InvalidState::class);
		$this->expectExceptionMessage(
			'Role role does not exist, add it with Orisai\Auth\Authorization\AuthorizationDataBuilder->addRole($role)',
		);

		$builder->removeAllow('role', 'article');
	}

	public function testAddRootChecksRole(): void
	{
		$builder = new AuthorizationDataBuilder();

		$this->expectException(InvalidState::class);
		$this->expectExceptionMessage(
			'Role role does not exist, add it with Orisai\Auth\Authorization\AuthorizationDataBuilder->addRole($role)',
		);

		$builder->addRoot('role');
	}

	public function testRemoveRootChecksRole(): void
	{
		$builder = new AuthorizationDataBuilder();

		$this->expectException(InvalidState::class);
		$this->expectExceptionMessage(
			'Role role does not exist, add it with Orisai\Auth\Authorization\AuthorizationDataBuilder->addRole($role)',
		);

		$builder->removeRoot('role');
	}

	public function testAllowChecksPrivilege(): void
	{
		$builder = new AuthorizationDataBuilder();
		$builder->addRole('role');

		$e = null;
		try {
			$builder->allow('role', 'unknown');
		} catch (UnknownPrivilege $e) {
			self::assertSame($e->getPrivilege(), 'unknown');
		}

		self::assertNotNull($e);
	}

	public function testDenyChecksPrivilege(): void
	{
		$builder = new AuthorizationDataBuilder();
		$builder->addRole('role');

		$e = null;
		try {
			$builder->removeAllow('role', 'unknown');
		} catch (UnknownPrivilege $e) {
			self::assertSame($e->getPrivilege(), 'unknown');
		}

		self::assertNotNull($e);
	}

	public function testThrowOnUnknownPrivilegeDisabled(): void
	{
		$builder = new AuthorizationDataBuilder();
		$builder->throwOnUnknownPrivilege = false;
		$builder->addRole('role');

		$exception = null;
		try {
			$builder->allow('role', 'unknown');
			$builder->removeAllow('role', 'unknown');
		} catch (Throwable $exception) {
			// Handled below
		}

		self::assertNull($exception);
	}

}
