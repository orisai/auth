<?php declare(strict_types = 1);

namespace Tests\Orisai\Auth\Unit\Authorization;

use Orisai\Auth\Authentication\IntIdentity;
use Orisai\Auth\Authorization\PrivilegeAuthorizer;
use Orisai\Exceptions\Logic\InvalidState;
use PHPUnit\Framework\TestCase;
use Tests\Orisai\Auth\Doubles\TestingPrivilegeAuthorizer;
use Throwable;

final class PrivilegeAuthorizerTest extends TestCase
{

	public function testPrivilegesData(): void
	{
		$authorizer = new TestingPrivilegeAuthorizer();

		$authorizer->addPrivilege('article');
		$authorizer->addPrivilege('article.view');
		$authorizer->addPrivilege('article.edit.owned');
		$authorizer->addPrivilege('article.edit.all');
		$authorizer->addPrivilege('article.edit');
		$authorizer->addPrivilege('account.create');

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
			$authorizer->getDebugPrivileges(),
		);

		self::assertSame(
			[
				'article.view',
				'article.edit.owned',
				'article.edit.all',
				'account.create',
			],
			$authorizer->getPrivileges(),
		);
	}

	public function testHasPrivilege(): void
	{
		$authorizer = new PrivilegeAuthorizer();

		self::assertTrue($authorizer->privilegeExists($authorizer::ALL_PRIVILEGES));
		self::assertFalse($authorizer->privilegeExists('article'));
		self::assertFalse($authorizer->privilegeExists('article.edit'));
		self::assertFalse($authorizer->privilegeExists('article.edit.all'));

		$authorizer->addPrivilege('article');
		self::assertTrue($authorizer->privilegeExists('article'));
		self::assertFalse($authorizer->privilegeExists('article.edit'));
		self::assertFalse($authorizer->privilegeExists('article.edit.all'));

		$authorizer->addPrivilege('article.edit.all');
		self::assertTrue($authorizer->privilegeExists('article'));
		self::assertTrue($authorizer->privilegeExists('article.edit'));
		self::assertTrue($authorizer->privilegeExists('article.edit.all'));

		self::assertTrue($authorizer->privilegeExists($authorizer::ALL_PRIVILEGES));
	}

	public function testRolesData(): void
	{
		$authorizer = new PrivilegeAuthorizer();

		$authorizer->addRole('supervisor');
		$authorizer->addRole('admin');
		$authorizer->addRole('guest');
		$authorizer->addRole('supervisor');
		$authorizer->addRole('guest');

		self::assertSame(
			[
				'supervisor',
				'admin',
				'guest',
			],
			$authorizer->getRoles(),
		);
	}

	public function testRolePrivilegesData(): void
	{
		$authorizer = new TestingPrivilegeAuthorizer();
		$role = 'editor';

		$authorizer->addPrivilege('article.view');
		$authorizer->addPrivilege('article.edit');
		$authorizer->addPrivilege('article.delete');
		$authorizer->addPrivilege('something');

		self::assertSame(
			[],
			$authorizer->getDebugRolePrivileges(),
		);
		self::assertSame(
			[],
			$authorizer->getRolePrivileges($role),
		);
		self::assertSame(
			[],
			$authorizer->getRolePrivileges('another-role'),
		);

		$authorizer->addRole($role);
		$authorizer->addRole('another-role');

		self::assertSame(
			[
				'editor' => [],
				'another-role' => [],
			],
			$authorizer->getDebugRolePrivileges(),
		);
		self::assertSame(
			[],
			$authorizer->getRolePrivileges($role),
		);
		self::assertSame(
			[],
			$authorizer->getRolePrivileges('another-role'),
		);

		$authorizer->allow($role, 'article.view');
		$authorizer->allow($role, 'article.edit');
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
			$authorizer->getDebugRolePrivileges(),
		);
		self::assertSame(
			[
				'article.view',
				'article.edit',
			],
			$authorizer->getRolePrivileges($role),
		);
		self::assertSame(
			[],
			$authorizer->getRolePrivileges('another-role'),
		);

		$authorizer->allow($role, 'something');
		$authorizer->allow('another-role', 'something');
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
			$authorizer->getDebugRolePrivileges(),
		);
		self::assertSame(
			[
				'article.view',
				'article.edit',
				'something',
			],
			$authorizer->getRolePrivileges($role),
		);
		self::assertSame(
			[
				'something',
			],
			$authorizer->getRolePrivileges('another-role'),
		);

		$authorizer->deny($role, 'article.edit');
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
			$authorizer->getDebugRolePrivileges(),
		);
		self::assertSame(
			[
				'article.view',
				'something',
			],
			$authorizer->getRolePrivileges($role),
		);
		self::assertSame(
			[
				'something',
			],
			$authorizer->getRolePrivileges('another-role'),
		);

		$authorizer->allow($role, 'article');
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
			$authorizer->getDebugRolePrivileges(),
		);
		self::assertSame(
			[
				'article.view',
				'article.edit',
				'article.delete',
				'something',
			],
			$authorizer->getRolePrivileges($role),
		);
		self::assertSame(
			[
				'something',
			],
			$authorizer->getRolePrivileges('another-role'),
		);

		$authorizer->deny($role, 'article');
		self::assertSame(
			[
				'editor' => [
					'something' => [],
				],
				'another-role' => [
					'something' => [],
				],
			],
			$authorizer->getDebugRolePrivileges(),
		);
		self::assertSame(
			[
				'something',
			],
			$authorizer->getRolePrivileges($role),
		);
		self::assertSame(
			[
				'something',
			],
			$authorizer->getRolePrivileges('another-role'),
		);
	}

	public function testRolesPrivilegesNotOverridden(): void
	{
		$authorizer = new TestingPrivilegeAuthorizer();

		$authorizer->addRole('role');
		$authorizer->addPrivilege('privilege');
		$authorizer->allow('role', 'privilege');

		$rolePrivilegesData = $authorizer->getDebugRolePrivileges();
		self::assertSame(
			[
				'role' => [
					'privilege' => [],
				],
			],
			$rolePrivilegesData,
		);

		$authorizer->addRole('role');
		self::assertSame(
			$rolePrivilegesData,
			$authorizer->getDebugRolePrivileges(),
		);
	}

	public function testNothingSet(): void
	{
		$authorizer = new PrivilegeAuthorizer();
		$role = 'role';
		$identity = new IntIdentity(1, [$role]);

		$authorizer->addRole($role);

		$authorizer->addPrivilege('article.view');
		$authorizer->addPrivilege('something');

		self::assertFalse($authorizer->hasPrivilege($identity, 'article'));
		self::assertFalse($authorizer->hasPrivilege($identity, 'article.view'));
		self::assertFalse($authorizer->hasPrivilege($identity, 'something'));
		self::assertFalse($authorizer->hasPrivilege($identity, $authorizer::ALL_PRIVILEGES));
		self::assertFalse($authorizer->isAllowed($identity, 'article'));
		self::assertFalse($authorizer->isAllowed($identity, 'article.view'));
		self::assertFalse($authorizer->isAllowed($identity, 'something'));
		self::assertFalse($authorizer->isAllowed($identity, $authorizer::ALL_PRIVILEGES));
	}

	public function testNoPrivilegesEqualToAllPrivileges(): void
	{
		$authorizer = new PrivilegeAuthorizer();
		$role = 'role';
		$identity = new IntIdentity(1, [$role]);

		$authorizer->addRole($role);

		// Edge case - no privileges are equal to all privileges
		self::assertTrue($authorizer->hasPrivilege($identity, $authorizer::ALL_PRIVILEGES));
		self::assertTrue($authorizer->isAllowed($identity, $authorizer::ALL_PRIVILEGES));
	}

	public function testAllAllowed(): void
	{
		$authorizer = new PrivilegeAuthorizer();
		$identity = new IntIdentity(1, ['supervisor']);

		$authorizer->addPrivilege('foo.bar.baz');
		$authorizer->addPrivilege('something.else');

		$authorizer->addRole('supervisor');

		$authorizer->allow('supervisor', $authorizer::ALL_PRIVILEGES);

		self::assertTrue($authorizer->hasPrivilege($identity, 'foo'));
		self::assertTrue($authorizer->hasPrivilege($identity, 'foo.bar'));
		self::assertTrue($authorizer->hasPrivilege($identity, 'foo.bar.baz'));
		self::assertTrue($authorizer->hasPrivilege($identity, 'something.else'));
		self::assertTrue($authorizer->hasPrivilege($identity, $authorizer::ALL_PRIVILEGES));
		self::assertTrue($authorizer->isAllowed($identity, 'foo'));
		self::assertTrue($authorizer->isAllowed($identity, 'foo.bar'));
		self::assertTrue($authorizer->isAllowed($identity, 'foo.bar.baz'));
		self::assertTrue($authorizer->isAllowed($identity, 'something.else'));
		self::assertTrue($authorizer->isAllowed($identity, $authorizer::ALL_PRIVILEGES));

		$authorizer->deny('supervisor', 'foo.bar');

		self::assertFalse($authorizer->hasPrivilege($identity, 'foo'));
		self::assertFalse($authorizer->hasPrivilege($identity, 'foo.bar'));
		self::assertFalse($authorizer->hasPrivilege($identity, 'foo.bar.baz'));
		self::assertTrue($authorizer->hasPrivilege($identity, 'something.else'));
		self::assertFalse($authorizer->hasPrivilege($identity, $authorizer::ALL_PRIVILEGES));
		self::assertFalse($authorizer->isAllowed($identity, 'foo'));
		self::assertFalse($authorizer->isAllowed($identity, 'foo.bar'));
		self::assertFalse($authorizer->isAllowed($identity, 'foo.bar.baz'));
		self::assertTrue($authorizer->isAllowed($identity, 'something.else'));
		self::assertFalse($authorizer->isAllowed($identity, $authorizer::ALL_PRIVILEGES));

		$authorizer->deny('supervisor', $authorizer::ALL_PRIVILEGES);

		self::assertFalse($authorizer->hasPrivilege($identity, 'foo'));
		self::assertFalse($authorizer->hasPrivilege($identity, 'foo.bar'));
		self::assertFalse($authorizer->hasPrivilege($identity, 'foo.bar.baz'));
		self::assertFalse($authorizer->hasPrivilege($identity, 'something.else'));
		self::assertFalse($authorizer->hasPrivilege($identity, $authorizer::ALL_PRIVILEGES));
		self::assertFalse($authorizer->isAllowed($identity, 'foo'));
		self::assertFalse($authorizer->isAllowed($identity, 'foo.bar'));
		self::assertFalse($authorizer->isAllowed($identity, 'foo.bar.baz'));
		self::assertFalse($authorizer->isAllowed($identity, 'something.else'));
		self::assertFalse($authorizer->isAllowed($identity, $authorizer::ALL_PRIVILEGES));
	}

	public function testAllAllowedRolesNotMixed(): void
	{
		$authorizer = new PrivilegeAuthorizer();
		$supervisor = new IntIdentity(1, ['supervisor']);
		$admin = new IntIdentity(2, ['admin']);

		$authorizer->addPrivilege('foo');

		$authorizer->addRole('supervisor');
		$authorizer->addRole('admin');

		$authorizer->allow('supervisor', $authorizer::ALL_PRIVILEGES);

		self::assertTrue($authorizer->hasPrivilege($supervisor, 'foo'));
		self::assertTrue($authorizer->hasPrivilege($supervisor, $authorizer::ALL_PRIVILEGES));
		self::assertTrue($authorizer->isAllowed($supervisor, 'foo'));
		self::assertTrue($authorizer->isAllowed($supervisor, $authorizer::ALL_PRIVILEGES));

		self::assertFalse($authorizer->hasPrivilege($admin, 'foo'));
		self::assertFalse($authorizer->hasPrivilege($admin, $authorizer::ALL_PRIVILEGES));
		self::assertFalse($authorizer->isAllowed($admin, 'foo'));
		self::assertFalse($authorizer->isAllowed($admin, $authorizer::ALL_PRIVILEGES));
	}

	public function testPrivilegesFromMultipleRoles(): void
	{
		$authorizer = new TestingPrivilegeAuthorizer();
		$identity = new IntIdentity(1, ['editor', 'editor-in-chief']);

		$authorizer->addPrivilege('article.view');
		$authorizer->addPrivilege('article.edit.owned');
		$authorizer->addPrivilege('article.edit.all');
		$authorizer->addPrivilege('article.publish');
		$authorizer->addPrivilege('article.delete');

		$authorizer->addRole('editor');
		$authorizer->addRole('editor-in-chief');

		$authorizer->allow('editor', 'article.view');
		$authorizer->allow('editor', 'article.edit.owned');

		$authorizer->allow('editor-in-chief', 'article.view');
		$authorizer->allow('editor-in-chief', 'article.edit.all');
		$authorizer->allow('editor-in-chief', 'article.publish');
		$authorizer->allow('editor-in-chief', 'article.delete');

		// requires privileges from one of roles
		self::assertTrue($authorizer->hasPrivilege($identity, 'article.view'));
		self::assertTrue($authorizer->hasPrivilege($identity, 'article.edit.owned'));
		self::assertTrue($authorizer->hasPrivilege($identity, 'article.edit.all'));
		self::assertTrue($authorizer->hasPrivilege($identity, 'article.publish'));
		self::assertTrue($authorizer->hasPrivilege($identity, 'article.delete'));
		self::assertTrue($authorizer->isAllowed($identity, 'article.view'));
		self::assertTrue($authorizer->isAllowed($identity, 'article.edit.owned'));
		self::assertTrue($authorizer->isAllowed($identity, 'article.edit.all'));
		self::assertTrue($authorizer->isAllowed($identity, 'article.publish'));
		self::assertTrue($authorizer->isAllowed($identity, 'article.delete'));

		// requires mix of privileges from both roles
		self::assertTrue($authorizer->hasPrivilege($identity, 'article.edit'));
		self::assertTrue($authorizer->hasPrivilege($identity, 'article'));
		self::assertTrue($authorizer->isAllowed($identity, 'article.edit'));
		self::assertTrue($authorizer->isAllowed($identity, 'article'));
	}

	public function testRolesNotMixed(): void
	{
		$authorizer = new PrivilegeAuthorizer();
		$supervisor = new IntIdentity(1, ['supervisor']);
		$admin = new IntIdentity(2, ['admin']);

		$authorizer->addPrivilege('foo');

		$authorizer->addRole('supervisor');
		$authorizer->addRole('admin');

		$authorizer->allow('supervisor', 'foo');

		self::assertTrue($authorizer->hasPrivilege($supervisor, $authorizer::ALL_PRIVILEGES));
		self::assertTrue($authorizer->hasPrivilege($supervisor, 'foo'));
		self::assertTrue($authorizer->isAllowed($supervisor, $authorizer::ALL_PRIVILEGES));
		self::assertTrue($authorizer->isAllowed($supervisor, 'foo'));

		self::assertFalse($authorizer->hasPrivilege($admin, $authorizer::ALL_PRIVILEGES));
		self::assertFalse($authorizer->hasPrivilege($admin, 'foo'));
		self::assertFalse($authorizer->isAllowed($admin, $authorizer::ALL_PRIVILEGES));
		self::assertFalse($authorizer->isAllowed($admin, 'foo'));
	}

	public function testActionsNotMixed(): void
	{
		$role = 'guest';
		$identity = new IntIdentity(1, [$role]);

		$authorizer = new PrivilegeAuthorizer();

		$authorizer->addPrivilege('admin');
		$authorizer->addPrivilege('front');

		$authorizer->addRole($role);

		self::assertFalse($authorizer->hasPrivilege($identity, 'front'));
		self::assertFalse($authorizer->hasPrivilege($identity, 'admin'));
		self::assertFalse($authorizer->isAllowed($identity, 'front'));
		self::assertFalse($authorizer->isAllowed($identity, 'admin'));

		$authorizer->allow($role, 'front');
		self::assertTrue($authorizer->hasPrivilege($identity, 'front'));
		self::assertFalse($authorizer->hasPrivilege($identity, 'admin'));
		self::assertTrue($authorizer->isAllowed($identity, 'front'));
		self::assertFalse($authorizer->isAllowed($identity, 'admin'));
	}

	public function testOverrideAllowThenDenyFromLeastSpecific(): void
	{
		$authorizer = new PrivilegeAuthorizer();
		$role = 'role';
		$identity = new IntIdentity(1, [$role]);

		$authorizer->addPrivilege('article.view');
		$authorizer->addPrivilege('article.edit');
		$authorizer->addPrivilege('article.delete');

		$authorizer->addRole($role);

		$authorizer->allow($role, 'article');
		self::assertTrue($authorizer->hasPrivilege($identity, 'article.view'));
		self::assertTrue($authorizer->hasPrivilege($identity, 'article.edit'));
		self::assertTrue($authorizer->hasPrivilege($identity, 'article.delete'));
		self::assertTrue($authorizer->hasPrivilege($identity, 'article'));
		self::assertTrue($authorizer->isAllowed($identity, 'article.view'));
		self::assertTrue($authorizer->isAllowed($identity, 'article.edit'));
		self::assertTrue($authorizer->isAllowed($identity, 'article.delete'));
		self::assertTrue($authorizer->isAllowed($identity, 'article'));

		$authorizer->allow($role, 'article.view');
		$authorizer->allow($role, 'article.edit');
		self::assertTrue($authorizer->hasPrivilege($identity, 'article.view'));
		self::assertTrue($authorizer->hasPrivilege($identity, 'article.edit'));
		self::assertTrue($authorizer->hasPrivilege($identity, 'article.delete'));
		self::assertTrue($authorizer->hasPrivilege($identity, 'article'));
		self::assertTrue($authorizer->isAllowed($identity, 'article.view'));
		self::assertTrue($authorizer->isAllowed($identity, 'article.edit'));
		self::assertTrue($authorizer->isAllowed($identity, 'article.delete'));
		self::assertTrue($authorizer->isAllowed($identity, 'article'));

		$authorizer->deny($role, 'article.edit');
		$authorizer->deny($role, 'article.delete');
		self::assertTrue($authorizer->hasPrivilege($identity, 'article.view'));
		self::assertFalse($authorizer->hasPrivilege($identity, 'article.edit'));
		self::assertFalse($authorizer->hasPrivilege($identity, 'article.delete'));
		self::assertFalse($authorizer->hasPrivilege($identity, 'article'));
		self::assertTrue($authorizer->isAllowed($identity, 'article.view'));
		self::assertFalse($authorizer->isAllowed($identity, 'article.edit'));
		self::assertFalse($authorizer->isAllowed($identity, 'article.delete'));
		self::assertFalse($authorizer->isAllowed($identity, 'article'));

		$authorizer->deny($role, 'article');
		self::assertFalse($authorizer->hasPrivilege($identity, 'article.view'));
		self::assertFalse($authorizer->hasPrivilege($identity, 'article.edit'));
		self::assertFalse($authorizer->hasPrivilege($identity, 'article.delete'));
		self::assertFalse($authorizer->hasPrivilege($identity, 'article'));
		self::assertFalse($authorizer->isAllowed($identity, 'article.view'));
		self::assertFalse($authorizer->isAllowed($identity, 'article.edit'));
		self::assertFalse($authorizer->isAllowed($identity, 'article.delete'));
		self::assertFalse($authorizer->isAllowed($identity, 'article'));
	}

	public function testOverrideDenyThenAllowFromLeastSpecific(): void
	{
		$authorizer = new PrivilegeAuthorizer();
		$role = 'role';
		$identity = new IntIdentity(1, [$role]);

		$authorizer->addPrivilege('article.view');
		$authorizer->addPrivilege('article.edit');
		$authorizer->addPrivilege('article.delete');

		$authorizer->addRole($role);

		$authorizer->deny($role, 'article');
		self::assertFalse($authorizer->hasPrivilege($identity, 'article.view'));
		self::assertFalse($authorizer->hasPrivilege($identity, 'article.edit'));
		self::assertFalse($authorizer->hasPrivilege($identity, 'article.delete'));
		self::assertFalse($authorizer->hasPrivilege($identity, 'article'));
		self::assertFalse($authorizer->isAllowed($identity, 'article.view'));
		self::assertFalse($authorizer->isAllowed($identity, 'article.edit'));
		self::assertFalse($authorizer->isAllowed($identity, 'article.delete'));
		self::assertFalse($authorizer->isAllowed($identity, 'article'));

		$authorizer->allow($role, 'article.view');
		$authorizer->allow($role, 'article.edit');
		self::assertTrue($authorizer->hasPrivilege($identity, 'article.view'));
		self::assertTrue($authorizer->hasPrivilege($identity, 'article.edit'));
		self::assertFalse($authorizer->hasPrivilege($identity, 'article.delete'));
		self::assertFalse($authorizer->hasPrivilege($identity, 'article'));
		self::assertTrue($authorizer->isAllowed($identity, 'article.view'));
		self::assertTrue($authorizer->isAllowed($identity, 'article.edit'));
		self::assertFalse($authorizer->isAllowed($identity, 'article.delete'));
		self::assertFalse($authorizer->isAllowed($identity, 'article'));

		$authorizer->deny($role, 'article.edit');
		$authorizer->allow($role, 'article.delete');
		self::assertTrue($authorizer->hasPrivilege($identity, 'article.view'));
		self::assertFalse($authorizer->hasPrivilege($identity, 'article.edit'));
		self::assertTrue($authorizer->hasPrivilege($identity, 'article.delete'));
		self::assertFalse($authorizer->hasPrivilege($identity, 'article'));
		self::assertTrue($authorizer->isAllowed($identity, 'article.view'));
		self::assertFalse($authorizer->isAllowed($identity, 'article.edit'));
		self::assertTrue($authorizer->isAllowed($identity, 'article.delete'));
		self::assertFalse($authorizer->isAllowed($identity, 'article'));
	}

	public function testOverrideAllowThenDenyFromMostSpecific(): void
	{
		$authorizer = new PrivilegeAuthorizer();
		$role = 'role';
		$identity = new IntIdentity(1, [$role]);

		$authorizer->addPrivilege('article.view');
		$authorizer->addPrivilege('article.edit');
		$authorizer->addPrivilege('article.delete');

		$authorizer->addRole($role);

		$authorizer->allow($role, 'article.view');
		$authorizer->allow($role, 'article.edit');
		self::assertTrue($authorizer->hasPrivilege($identity, 'article.view'));
		self::assertTrue($authorizer->hasPrivilege($identity, 'article.edit'));
		self::assertFalse($authorizer->hasPrivilege($identity, 'article.delete'));
		self::assertFalse($authorizer->hasPrivilege($identity, 'article'));
		self::assertTrue($authorizer->isAllowed($identity, 'article.view'));
		self::assertTrue($authorizer->isAllowed($identity, 'article.edit'));
		self::assertFalse($authorizer->isAllowed($identity, 'article.delete'));
		self::assertFalse($authorizer->isAllowed($identity, 'article'));

		$authorizer->deny($role, 'article.edit');
		self::assertTrue($authorizer->hasPrivilege($identity, 'article.view'));
		self::assertFalse($authorizer->hasPrivilege($identity, 'article.edit'));
		self::assertFalse($authorizer->hasPrivilege($identity, 'article.delete'));
		self::assertFalse($authorizer->hasPrivilege($identity, 'article'));
		self::assertTrue($authorizer->isAllowed($identity, 'article.view'));
		self::assertFalse($authorizer->isAllowed($identity, 'article.edit'));
		self::assertFalse($authorizer->isAllowed($identity, 'article.delete'));
		self::assertFalse($authorizer->isAllowed($identity, 'article'));

		$authorizer->deny($role, 'article');
		self::assertFalse($authorizer->hasPrivilege($identity, 'article.view'));
		self::assertFalse($authorizer->hasPrivilege($identity, 'article.edit'));
		self::assertFalse($authorizer->hasPrivilege($identity, 'article.delete'));
		self::assertFalse($authorizer->hasPrivilege($identity, 'article'));
		self::assertFalse($authorizer->isAllowed($identity, 'article.view'));
		self::assertFalse($authorizer->isAllowed($identity, 'article.edit'));
		self::assertFalse($authorizer->isAllowed($identity, 'article.delete'));
		self::assertFalse($authorizer->isAllowed($identity, 'article'));
	}

	public function testAuthorizerDontDefineAllIdentityRoles(): void
	{
		$authorizer = new PrivilegeAuthorizer();
		$identity = new IntIdentity(1, ['not-defined-by-authorizer']);

		$authorizer->addPrivilege('something');

		self::assertFalse($authorizer->hasPrivilege($identity, 'something'));
		self::assertFalse($authorizer->isAllowed($identity, 'something'));
	}

	public function testAllowChecksRole(): void
	{
		$authorizer = new PrivilegeAuthorizer();

		$this->expectException(InvalidState::class);
		$this->expectExceptionMessage(
			'Role role does not exist, add it with Orisai\Auth\Authorization\PrivilegeAuthorizer->addRole($role)',
		);

		$authorizer->allow('role', 'article');
	}

	public function testDenyChecksRole(): void
	{
		$authorizer = new PrivilegeAuthorizer();

		$this->expectException(InvalidState::class);
		$this->expectExceptionMessage(
			'Role role does not exist, add it with Orisai\Auth\Authorization\PrivilegeAuthorizer->addRole($role)',
		);

		$authorizer->deny('role', 'article');
	}

	public function testAllowChecksPrivilege(): void
	{
		$authorizer = new PrivilegeAuthorizer();
		$authorizer->throwOnUnknownRolePrivilege = true;
		$authorizer->addRole('role');

		$this->expectException(InvalidState::class);
		$this->expectExceptionMessage(
			'Privilege unknown is unknown, add with addPrivilege() before calling Orisai\Auth\Authorization\PrivilegeAuthorizer->allow()',
		);

		$authorizer->allow('role', 'unknown');
	}

	public function testDenyChecksPrivilege(): void
	{
		$authorizer = new PrivilegeAuthorizer();
		$authorizer->throwOnUnknownRolePrivilege = true;
		$authorizer->addRole('role');

		$this->expectException(InvalidState::class);
		$this->expectExceptionMessage(
			'Privilege unknown is unknown, add with addPrivilege() before calling Orisai\Auth\Authorization\PrivilegeAuthorizer->deny()',
		);

		$authorizer->deny('role', 'unknown');
	}

	public function testAssigningUnknownRolePrivilegeDoesNotFailByDefault(): void
	{
		$authorizer = new PrivilegeAuthorizer();
		$authorizer->addRole('role');

		$exception = null;
		try {
			$authorizer->allow('role', 'unknown');
			$authorizer->deny('role', 'unknown');
		} catch (Throwable $exception) {
			// Handled below
		}

		self::assertNull($exception);
	}

	public function testIsAllowedChecksPrivilege(): void
	{
		$authorizer = new PrivilegeAuthorizer();
		$authorizer->addRole('role');

		$identity = new IntIdentity(1, ['role']);

		$this->expectException(InvalidState::class);
		$this->expectExceptionMessage(
			'Privilege unknown is unknown, add with addPrivilege() before calling Orisai\Auth\Authorization\PrivilegeAuthorizer->isAllowed()',
		);

		$authorizer->isAllowed($identity, 'unknown');
	}

	public function testHasPrivilegeChecksPrivilege(): void
	{
		$authorizer = new PrivilegeAuthorizer();
		$authorizer->addRole('role');

		$identity = new IntIdentity(1, ['role']);

		$this->expectException(InvalidState::class);
		$this->expectExceptionMessage(
			'Privilege unknown is unknown, add with addPrivilege() before calling Orisai\Auth\Authorization\PrivilegeAuthorizer->hasPrivilege()',
		);

		$authorizer->hasPrivilege($identity, 'unknown');
	}

}
