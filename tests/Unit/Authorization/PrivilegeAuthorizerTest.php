<?php declare(strict_types = 1);

namespace Tests\Orisai\Auth\Unit\Authorization;

use Orisai\Auth\Authentication\IntIdentity;
use Orisai\Auth\Authorization\Authorizer;
use Orisai\Auth\Authorization\NoRequirements;
use Orisai\Auth\Authorization\PrivilegeAuthorizer;
use Orisai\Auth\Authorization\SimplePolicyManager;
use Orisai\Exceptions\Logic\InvalidArgument;
use Orisai\Exceptions\Logic\InvalidState;
use PHPUnit\Framework\TestCase;
use stdClass;
use Tests\Orisai\Auth\Doubles\Article;
use Tests\Orisai\Auth\Doubles\ArticleEditOwnedPolicy;
use Tests\Orisai\Auth\Doubles\ArticleEditPolicy;
use Tests\Orisai\Auth\Doubles\NeverPassPolicy;
use Tests\Orisai\Auth\Doubles\NoRequirementsPolicy;
use Tests\Orisai\Auth\Doubles\NullableRequirementsPolicy;
use Tests\Orisai\Auth\Doubles\TestingPrivilegeAuthorizer;
use Tests\Orisai\Auth\Doubles\User;
use Throwable;

final class PrivilegeAuthorizerTest extends TestCase
{

	private function policies(): SimplePolicyManager
	{
		return new SimplePolicyManager();
	}

	public function testPrivilegesData(): void
	{
		$authorizer = new TestingPrivilegeAuthorizer($this->policies());

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
		$authorizer = new PrivilegeAuthorizer($this->policies());

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
		$authorizer = new PrivilegeAuthorizer($this->policies());

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
		$authorizer = new TestingPrivilegeAuthorizer($this->policies());
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
			$authorizer->getAllowedPrivilegesForRole($role),
		);
		self::assertSame(
			[],
			$authorizer->getAllowedPrivilegesForRole('another-role'),
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
			$authorizer->getAllowedPrivilegesForRole($role),
		);
		self::assertSame(
			[],
			$authorizer->getAllowedPrivilegesForRole('another-role'),
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
			$authorizer->getAllowedPrivilegesForRole($role),
		);
		self::assertSame(
			[],
			$authorizer->getAllowedPrivilegesForRole('another-role'),
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
			$authorizer->getAllowedPrivilegesForRole($role),
		);
		self::assertSame(
			[
				'something',
			],
			$authorizer->getAllowedPrivilegesForRole('another-role'),
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
			$authorizer->getAllowedPrivilegesForRole($role),
		);
		self::assertSame(
			[
				'something',
			],
			$authorizer->getAllowedPrivilegesForRole('another-role'),
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
			$authorizer->getAllowedPrivilegesForRole($role),
		);
		self::assertSame(
			[
				'something',
			],
			$authorizer->getAllowedPrivilegesForRole('another-role'),
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
			$authorizer->getAllowedPrivilegesForRole($role),
		);
		self::assertSame(
			[
				'something',
			],
			$authorizer->getAllowedPrivilegesForRole('another-role'),
		);
	}

	public function testRolesPrivilegesNotOverridden(): void
	{
		$authorizer = new TestingPrivilegeAuthorizer($this->policies());

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
		$authorizer = new PrivilegeAuthorizer($this->policies());
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
		$authorizer = new PrivilegeAuthorizer($this->policies());
		$role = 'role';
		$identity = new IntIdentity(1, [$role]);

		$authorizer->addRole($role);

		// Edge case - no privileges are equal to all privileges
		self::assertTrue($authorizer->hasPrivilege($identity, $authorizer::ALL_PRIVILEGES));
		self::assertTrue($authorizer->isAllowed($identity, $authorizer::ALL_PRIVILEGES));
	}

	public function testAllAllowed(): void
	{
		$authorizer = new PrivilegeAuthorizer($this->policies());
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
		$authorizer = new PrivilegeAuthorizer($this->policies());
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
		$authorizer = new TestingPrivilegeAuthorizer($this->policies());
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
		$authorizer = new PrivilegeAuthorizer($this->policies());
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

		$authorizer = new PrivilegeAuthorizer($this->policies());

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
		$authorizer = new PrivilegeAuthorizer($this->policies());
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
		$authorizer = new PrivilegeAuthorizer($this->policies());
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
		$authorizer = new PrivilegeAuthorizer($this->policies());
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

	public function testSkipUnknownRoles(): void
	{
		$authorizer = new PrivilegeAuthorizer($this->policies());
		$identity = new IntIdentity(1, ['unknown']);

		$authorizer->addRole('known');
		$authorizer->addPrivilege('something');
		$authorizer->allow('known', 'something');

		self::assertFalse($authorizer->hasPrivilege($identity, 'something'));
		self::assertFalse($authorizer->isAllowed($identity, 'something'));

		$identity = new IntIdentity(1, ['unknown', 'known']);
		self::assertTrue($authorizer->hasPrivilege($identity, 'something'));
		self::assertTrue($authorizer->isAllowed($identity, 'something'));
	}

	public function testAllowChecksRole(): void
	{
		$authorizer = new PrivilegeAuthorizer($this->policies());

		$this->expectException(InvalidState::class);
		$this->expectExceptionMessage(
			'Role role does not exist, add it with Orisai\Auth\Authorization\PrivilegeAuthorizer->addRole($role)',
		);

		$authorizer->allow('role', 'article');
	}

	public function testDenyChecksRole(): void
	{
		$authorizer = new PrivilegeAuthorizer($this->policies());

		$this->expectException(InvalidState::class);
		$this->expectExceptionMessage(
			'Role role does not exist, add it with Orisai\Auth\Authorization\PrivilegeAuthorizer->addRole($role)',
		);

		$authorizer->deny('role', 'article');
	}

	public function testAllowChecksPrivilege(): void
	{
		$authorizer = new PrivilegeAuthorizer($this->policies());
		$authorizer->throwOnUnknownRolePrivilege = true;
		$authorizer->addRole('role');

		$this->expectException(InvalidState::class);
		$this->expectExceptionMessage(<<<'MSG'
Context: Trying to call Orisai\Auth\Authorization\PrivilegeAuthorizer->allow().
Problem: Privilege unknown is unknown.
Solution: Add privilege to authorizer first via addPrivilege().
MSG);

		$authorizer->allow('role', 'unknown');
	}

	public function testDenyChecksPrivilege(): void
	{
		$authorizer = new PrivilegeAuthorizer($this->policies());
		$authorizer->throwOnUnknownRolePrivilege = true;
		$authorizer->addRole('role');

		$this->expectException(InvalidState::class);
		$this->expectExceptionMessage(<<<'MSG'
Context: Trying to call Orisai\Auth\Authorization\PrivilegeAuthorizer->deny().
Problem: Privilege unknown is unknown.
Solution: Add privilege to authorizer first via addPrivilege().
MSG);

		$authorizer->deny('role', 'unknown');
	}

	public function testAssigningUnknownRolePrivilegeDoesNotFailByDefault(): void
	{
		$authorizer = new PrivilegeAuthorizer($this->policies());
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

	public function testIsAllowedWithPrivilegeChecksPrivilege(): void
	{
		$authorizer = new PrivilegeAuthorizer($this->policies());
		$authorizer->addRole('role');

		$identity = new IntIdentity(1, ['role']);

		$this->expectException(InvalidState::class);
		$this->expectExceptionMessage(<<<'MSG'
Context: Trying to call
         Orisai\Auth\Authorization\PrivilegeAuthorizer->isAllowed().
Problem: Privilege unknown is unknown.
Solution: Add privilege to authorizer first via addPrivilege().
MSG);

		$authorizer->isAllowed($identity, 'unknown');
	}

	public function testIsAllowedWithPolicyChecksPrivilege(): void
	{
		$policyManager = $this->policies();
		$policyManager->add(new ArticleEditPolicy());

		$authorizer = new PrivilegeAuthorizer($policyManager);

		$this->expectException(InvalidState::class);
		$this->expectExceptionMessage(<<<'MSG'
Context: Trying to call
         Orisai\Auth\Authorization\PrivilegeAuthorizer->isAllowed().
Problem: Privilege article.edit is unknown.
Solution: Add privilege to authorizer first via addPrivilege().
MSG);

		$authorizer->isAllowed(new IntIdentity(1, []), ArticleEditPolicy::getPrivilege());
	}

	public function testHasPrivilegeChecksPrivilege(): void
	{
		$authorizer = new PrivilegeAuthorizer($this->policies());
		$authorizer->addRole('role');

		$identity = new IntIdentity(1, ['role']);

		$this->expectException(InvalidState::class);
		$this->expectExceptionMessage(<<<'MSG'
Context: Trying to call
         Orisai\Auth\Authorization\PrivilegeAuthorizer->hasPrivilege().
Problem: Privilege unknown is unknown.
Solution: Add privilege to authorizer first via addPrivilege().
MSG);

		$authorizer->hasPrivilege($identity, 'unknown');
	}

	public function testIsAllowedWithoutPolicyForbidsRequirements(): void
	{
		$authorizer = new PrivilegeAuthorizer($this->policies());

		$this->expectException(InvalidArgument::class);
		$this->expectExceptionMessage(<<<'MSG'
Context: Trying to check privilege article.edit via
         Orisai\Auth\Authorization\PrivilegeAuthorizer->isAllowed().
Problem: Passed requirement object (type of stdClass) which is not allowed by
         privilege without policy.
Solution: Do not pass the requirement object or define policy which can handle
          it.
MSG);

		$authorizer->isAllowed(new IntIdentity(1, []), 'article.edit', new stdClass());
	}

	public function testPolicyRequirementsOfInvalidType(): void
	{
		$policyManager = $this->policies();
		$policyManager->add(new ArticleEditPolicy());

		$authorizer = new PrivilegeAuthorizer($policyManager);
		$authorizer->addPrivilege(ArticleEditPolicy::getPrivilege());

		$this->expectException(InvalidArgument::class);
		$this->expectExceptionMessage(<<<'MSG'
Context: Trying to check privilege article.edit via
         Orisai\Auth\Authorization\PrivilegeAuthorizer->isAllowed().
Problem: Passed requirements are of type stdClass, which is not supported by
         Tests\Orisai\Auth\Doubles\ArticleEditPolicy.
Solution: Pass requirements of type Tests\Orisai\Auth\Doubles\Article or change
          policy or its requirements.
MSG);

		$authorizer->isAllowed(new IntIdentity(1, []), ArticleEditPolicy::getPrivilege(), new stdClass());
	}

	public function testPolicyWithNoRequirements(): void
	{
		$policyManager = $this->policies();
		$policyManager->add(new NoRequirementsPolicy());

		$authorizer = new PrivilegeAuthorizer($policyManager);
		$authorizer->addPrivilege(NoRequirementsPolicy::getPrivilege());

		self::assertFalse($authorizer->isAllowed(new IntIdentity(1, []), NoRequirementsPolicy::getPrivilege(), null));
		self::assertFalse(
			$authorizer->isAllowed(new IntIdentity(1, []), NoRequirementsPolicy::getPrivilege(), new NoRequirements()),
		);
	}

	public function testPolicyNullableRequirementWithNull(): void
	{
		$policyManager = $this->policies();
		$policyManager->add(new NullableRequirementsPolicy());

		$authorizer = new PrivilegeAuthorizer($policyManager);
		$authorizer->addPrivilege(NullableRequirementsPolicy::getPrivilege());

		self::assertFalse(
			$authorizer->isAllowed(new IntIdentity(1, []), NullableRequirementsPolicy::getPrivilege(), null),
		);
	}

	public function testPolicyNonNullableRequirementWithNull(): void
	{
		$policyManager = $this->policies();
		$policyManager->add(new ArticleEditPolicy());

		$authorizer = new PrivilegeAuthorizer($policyManager);
		$authorizer->addPrivilege(ArticleEditPolicy::getPrivilege());

		$this->expectException(InvalidArgument::class);
		$this->expectExceptionMessage(<<<'MSG'
Context: Trying to check privilege article.edit via
         Orisai\Auth\Authorization\PrivilegeAuthorizer->isAllowed().
Problem: Policy requirements are missing, which is not supported by
         Tests\Orisai\Auth\Doubles\ArticleEditPolicy.
Solution: Pass requirements of type Tests\Orisai\Auth\Doubles\Article or mark
          policy requirements nullable or change them to
          Orisai\Auth\Authorization\NoRequirements.
MSG);

		$authorizer->isAllowed(new IntIdentity(1, []), ArticleEditPolicy::getPrivilege(), null);
	}

	public function testPolicyResourceOwner(): void
	{
		$policyManager = $this->policies();
		$policyManager->add(new ArticleEditPolicy());
		$policyManager->add(new ArticleEditOwnedPolicy());
		$policyManager->add(new NeverPassPolicy());

		$authorizer = new PrivilegeAuthorizer($policyManager);

		$authorizer->addPrivilege('article.edit.all');
		$authorizer->addPrivilege('article.edit.owned');
		$authorizer->addPrivilege('article.view');
		$authorizer->addPrivilege(NeverPassPolicy::getPrivilege());

		$authorizer->addRole('owner');
		$authorizer->addRole('editor');
		$authorizer->addRole('supervisor');

		$authorizer->allow('editor', 'article.edit.all');
		$authorizer->allow('owner', 'article.edit.owned');
		$authorizer->allow('supervisor', Authorizer::ALL_PRIVILEGES);

		$user1 = new User(1);
		$article1 = new Article($user1);

		// Don't have privileges
		$identity1 = new IntIdentity($user1->getId(), []);

		self::assertFalse($authorizer->isAllowed($identity1, ...ArticleEditPolicy::get($article1)));
		self::assertFalse($authorizer->isAllowed($identity1, ...ArticleEditOwnedPolicy::get($article1)));

		// Has access to owned resources
		$identity1 = new IntIdentity($user1->getId(), ['owner']);

		self::assertTrue($authorizer->hasPrivilege($identity1, 'article.edit.owned'));
		self::assertTrue($authorizer->isAllowed($identity1, ...ArticleEditPolicy::get($article1)));
		self::assertTrue($authorizer->isAllowed($identity1, ...ArticleEditOwnedPolicy::get($article1)));

		// Does not have access to resource of another user
		$user2 = new User(2);
		$identity2 = new IntIdentity($user2->getId(), ['owner']);
		self::assertTrue($authorizer->hasPrivilege($identity2, 'article.edit.owned'));
		self::assertFalse($authorizer->isAllowed($identity2, ...ArticleEditPolicy::get($article1)));

		// Has access to resources of all users
		$identity1 = new IntIdentity($user1->getId(), ['owner', 'editor']);
		$article2 = new Article($user2);
		self::assertTrue($authorizer->isAllowed($identity1, ...ArticleEditPolicy::get($article2)));

		// - but not other resources
		self::assertFalse($authorizer->isAllowed($identity1, 'article.view'));
		self::assertFalse($authorizer->isAllowed($identity1, 'article'));
		self::assertFalse($authorizer->isAllowed($identity1, Authorizer::ALL_PRIVILEGES));

		// Has access to all resources
		$identity1 = new IntIdentity($user1->getId(), ['supervisor']);

		self::assertTrue($authorizer->isAllowed($identity1, ...ArticleEditPolicy::get($article2)));

		self::assertTrue($authorizer->isAllowed($identity1, 'article.view'));
		self::assertTrue($authorizer->isAllowed($identity1, 'article'));
		self::assertTrue($authorizer->isAllowed($identity1, Authorizer::ALL_PRIVILEGES));

		// - except these which have defined policy which does not allow it
		self::assertTrue($authorizer->hasPrivilege($identity1, NeverPassPolicy::getPrivilege()));
		self::assertFalse($authorizer->isAllowed($identity1, ...NeverPassPolicy::get()));
	}

}
