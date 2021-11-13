<?php declare(strict_types = 1);

namespace Tests\Orisai\Auth\Unit\Authorization;

use Orisai\Auth\Authorization\AuthorizationDataBuilder;
use Orisai\Auth\Authorization\Authorizer;
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
		self::assertTrue($data->privilegeExists(Authorizer::ALL_PRIVILEGES));
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
		self::assertTrue($data->privilegeExists(Authorizer::ALL_PRIVILEGES));
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

	public function testRoleAllowedPrivileges(): void
	{
		$builder = new AuthorizationDataBuilder();

		$builder->addPrivilege('article.view');
		$builder->addPrivilege('article.edit');
		$builder->addPrivilege('article.delete');
		$builder->addPrivilege('something');
		$data = $builder->build();

		$role = 'editor';

		self::assertSame(
			[],
			$data->getRawRoleAllowedPrivileges(),
		);
		self::assertSame(
			[],
			$data->getAllowedPrivilegesForRole($role),
		);
		self::assertSame(
			[],
			$data->getAllowedPrivilegesForRole('another-role'),
		);

		$builder->addRole($role);
		$builder->addRole('another-role');
		$data = $builder->build();

		self::assertSame(
			[
				'editor' => [],
				'another-role' => [],
			],
			$data->getRawRoleAllowedPrivileges(),
		);
		self::assertSame(
			[],
			$data->getAllowedPrivilegesForRole($role),
		);
		self::assertSame(
			[],
			$data->getAllowedPrivilegesForRole('another-role'),
		);

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
				'another-role' => [],
			],
			$data->getRawRoleAllowedPrivileges(),
		);
		self::assertSame(
			[
				'article.view',
				'article.edit',
			],
			$data->getAllowedPrivilegesForRole($role),
		);
		self::assertSame(
			[],
			$data->getAllowedPrivilegesForRole('another-role'),
		);

		$builder->allow($role, 'something');
		$builder->allow('another-role', 'something');
		$data = $builder->build();
		self::assertSame(
			[
				'editor' => [
					'article' => [
						'view' => [],
						'edit' => [],
					],
					'something' => [],
				],
				'another-role' => [
					'something' => [],
				],
			],
			$data->getRawRoleAllowedPrivileges(),
		);
		self::assertSame(
			[
				'article.view',
				'article.edit',
				'something',
			],
			$data->getAllowedPrivilegesForRole($role),
		);
		self::assertSame(
			[
				'something',
			],
			$data->getAllowedPrivilegesForRole('another-role'),
		);

		$builder->deny($role, 'article.edit');
		$data = $builder->build();
		self::assertSame(
			[
				'editor' => [
					'article' => [
						'view' => [],
					],
					'something' => [],
				],
				'another-role' => [
					'something' => [],
				],
			],
			$data->getRawRoleAllowedPrivileges(),
		);
		self::assertSame(
			[
				'article.view',
				'something',
			],
			$data->getAllowedPrivilegesForRole($role),
		);
		self::assertSame(
			[
				'something',
			],
			$data->getAllowedPrivilegesForRole('another-role'),
		);

		$builder->allow($role, 'article');
		$data = $builder->build();
		self::assertSame(
			[
				'editor' => [
					'article' => [
						'view' => [],
						'edit' => [],
						'delete' => [],
					],
					'something' => [],
				],
				'another-role' => [
					'something' => [],
				],
			],
			$data->getRawRoleAllowedPrivileges(),
		);
		self::assertSame(
			[
				'article.view',
				'article.edit',
				'article.delete',
				'something',
			],
			$data->getAllowedPrivilegesForRole($role),
		);
		self::assertSame(
			[
				'something',
			],
			$data->getAllowedPrivilegesForRole('another-role'),
		);

		$builder->deny($role, 'article');
		$data = $builder->build();
		self::assertSame(
			[
				'editor' => [
					'something' => [],
				],
				'another-role' => [
					'something' => [],
				],
			],
			$data->getRawRoleAllowedPrivileges(),
		);
		self::assertSame(
			[
				'something',
			],
			$data->getAllowedPrivilegesForRole($role),
		);
		self::assertSame(
			[
				'something',
			],
			$data->getAllowedPrivilegesForRole('another-role'),
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

		$builder->deny('role', 'article');
	}

	public function testAllowChecksPrivilege(): void
	{
		$builder = new AuthorizationDataBuilder();
		$builder->throwOnUnknownRolePrivilege = true;
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
		$builder->throwOnUnknownRolePrivilege = true;
		$builder->addRole('role');

		$e = null;
		try {
			$builder->deny('role', 'unknown');
		} catch (UnknownPrivilege $e) {
			self::assertSame($e->getPrivilege(), 'unknown');
		}

		self::assertNotNull($e);
	}

	public function testAssigningUnknownRolePrivilegeDoesNotFailByDefault(): void
	{
		$builder = new AuthorizationDataBuilder();
		$builder->addRole('role');

		$exception = null;
		try {
			$builder->allow('role', 'unknown');
			$builder->deny('role', 'unknown');
		} catch (Throwable $exception) {
			// Handled below
		}

		self::assertNull($exception);
	}

}
