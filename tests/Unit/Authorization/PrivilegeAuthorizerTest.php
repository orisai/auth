<?php declare(strict_types = 1);

namespace Tests\Orisai\Auth\Unit\Authorization;

use Orisai\Auth\Authentication\IntIdentity;
use Orisai\Auth\Authorization\AuthorizationDataBuilder;
use Orisai\Auth\Authorization\Authorizer;
use Orisai\Auth\Authorization\NoRequirements;
use Orisai\Auth\Authorization\PrivilegeAuthorizer;
use Orisai\Auth\Authorization\SimplePolicyManager;
use Orisai\Auth\Authorization\UnknownPrivilege;
use Orisai\Exceptions\Logic\InvalidArgument;
use PHPUnit\Framework\TestCase;
use stdClass;
use Tests\Orisai\Auth\Doubles\Article;
use Tests\Orisai\Auth\Doubles\ArticleEditOwnedPolicy;
use Tests\Orisai\Auth\Doubles\ArticleEditPolicy;
use Tests\Orisai\Auth\Doubles\NeverPassPolicy;
use Tests\Orisai\Auth\Doubles\NoRequirementsPolicy;
use Tests\Orisai\Auth\Doubles\NullableRequirementsPolicy;
use Tests\Orisai\Auth\Doubles\User;

final class PrivilegeAuthorizerTest extends TestCase
{

	private function policies(): SimplePolicyManager
	{
		return new SimplePolicyManager();
	}

	public function testGetData(): void
	{
		$builder = new AuthorizationDataBuilder();
		$data = $builder->build();

		$authorizer = new PrivilegeAuthorizer($this->policies(), $data);
		self::assertSame($data, $authorizer->getData());
	}

	public function testNothingSet(): void
	{
		$builder = new AuthorizationDataBuilder();

		$role = 'role';
		$builder->addRole($role);

		$builder->addPrivilege('article.view');
		$builder->addPrivilege('something');

		$authorizer = new PrivilegeAuthorizer($this->policies(), $builder->build());
		$identity = new IntIdentity(1, [$role]);

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
		$role = 'role';

		$builder = new AuthorizationDataBuilder();
		$builder->addRole($role);

		$authorizer = new PrivilegeAuthorizer($this->policies(), $builder->build());
		$identity = new IntIdentity(1, [$role]);

		// Edge case - no privileges are equal to all privileges
		self::assertTrue($authorizer->hasPrivilege($identity, $authorizer::ALL_PRIVILEGES));
		self::assertTrue($authorizer->isAllowed($identity, $authorizer::ALL_PRIVILEGES));
	}

	public function testAllAllowed(): void
	{
		$builder = new AuthorizationDataBuilder();

		$builder->addPrivilege('foo.bar.baz');
		$builder->addPrivilege('something.else');

		$builder->addRole('supervisor');

		$builder->allow('supervisor', Authorizer::ALL_PRIVILEGES);

		$authorizer = new PrivilegeAuthorizer($this->policies(), $builder->build());
		$identity = new IntIdentity(1, ['supervisor']);

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

		$builder->deny('supervisor', 'foo.bar');
		$authorizer = new PrivilegeAuthorizer($this->policies(), $builder->build());

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

		$builder->deny('supervisor', $authorizer::ALL_PRIVILEGES);
		$authorizer = new PrivilegeAuthorizer($this->policies(), $builder->build());

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
		$builder = new AuthorizationDataBuilder();

		$builder->addPrivilege('foo');

		$builder->addRole('supervisor');
		$builder->addRole('admin');

		$builder->allow('supervisor', Authorizer::ALL_PRIVILEGES);

		$authorizer = new PrivilegeAuthorizer($this->policies(), $builder->build());
		$supervisor = new IntIdentity(1, ['supervisor']);
		$admin = new IntIdentity(2, ['admin']);

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
		$builder = new AuthorizationDataBuilder();

		$builder->addPrivilege('article.view');
		$builder->addPrivilege('article.edit.owned');
		$builder->addPrivilege('article.edit.all');
		$builder->addPrivilege('article.publish');
		$builder->addPrivilege('article.delete');

		$builder->addRole('editor');
		$builder->addRole('editor-in-chief');

		$builder->allow('editor', 'article.view');
		$builder->allow('editor', 'article.edit.owned');

		$builder->allow('editor-in-chief', 'article.view');
		$builder->allow('editor-in-chief', 'article.edit.all');
		$builder->allow('editor-in-chief', 'article.publish');
		$builder->allow('editor-in-chief', 'article.delete');

		$authorizer = new PrivilegeAuthorizer($this->policies(), $builder->build());
		$identity = new IntIdentity(1, ['editor', 'editor-in-chief']);

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
		$builder = new AuthorizationDataBuilder();

		$builder->addPrivilege('foo');

		$builder->addRole('supervisor');
		$builder->addRole('admin');

		$builder->allow('supervisor', 'foo');

		$authorizer = new PrivilegeAuthorizer($this->policies(), $builder->build());
		$supervisor = new IntIdentity(1, ['supervisor']);
		$admin = new IntIdentity(2, ['admin']);

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
		$builder = new AuthorizationDataBuilder();

		$builder->addPrivilege('admin');
		$builder->addPrivilege('front');

		$role = 'guest';
		$builder->addRole($role);

		$identity = new IntIdentity(1, [$role]);

		$authorizer = new PrivilegeAuthorizer($this->policies(), $builder->build());

		self::assertFalse($authorizer->hasPrivilege($identity, 'front'));
		self::assertFalse($authorizer->hasPrivilege($identity, 'admin'));
		self::assertFalse($authorizer->isAllowed($identity, 'front'));
		self::assertFalse($authorizer->isAllowed($identity, 'admin'));

		$builder->allow($role, 'front');
		$authorizer = new PrivilegeAuthorizer($this->policies(), $builder->build());
		self::assertTrue($authorizer->hasPrivilege($identity, 'front'));
		self::assertFalse($authorizer->hasPrivilege($identity, 'admin'));
		self::assertTrue($authorizer->isAllowed($identity, 'front'));
		self::assertFalse($authorizer->isAllowed($identity, 'admin'));
	}

	public function testOverrideAllowThenDenyFromLeastSpecific(): void
	{
		$builder = new AuthorizationDataBuilder();
		$role = 'role';
		$identity = new IntIdentity(1, [$role]);

		$builder->addPrivilege('article.view');
		$builder->addPrivilege('article.edit');
		$builder->addPrivilege('article.delete');

		$builder->addRole($role);

		$builder->allow($role, 'article');
		$authorizer = new PrivilegeAuthorizer($this->policies(), $builder->build());
		self::assertTrue($authorizer->hasPrivilege($identity, 'article.view'));
		self::assertTrue($authorizer->hasPrivilege($identity, 'article.edit'));
		self::assertTrue($authorizer->hasPrivilege($identity, 'article.delete'));
		self::assertTrue($authorizer->hasPrivilege($identity, 'article'));
		self::assertTrue($authorizer->isAllowed($identity, 'article.view'));
		self::assertTrue($authorizer->isAllowed($identity, 'article.edit'));
		self::assertTrue($authorizer->isAllowed($identity, 'article.delete'));
		self::assertTrue($authorizer->isAllowed($identity, 'article'));

		$builder->allow($role, 'article.view');
		$builder->allow($role, 'article.edit');
		$authorizer = new PrivilegeAuthorizer($this->policies(), $builder->build());
		self::assertTrue($authorizer->hasPrivilege($identity, 'article.view'));
		self::assertTrue($authorizer->hasPrivilege($identity, 'article.edit'));
		self::assertTrue($authorizer->hasPrivilege($identity, 'article.delete'));
		self::assertTrue($authorizer->hasPrivilege($identity, 'article'));
		self::assertTrue($authorizer->isAllowed($identity, 'article.view'));
		self::assertTrue($authorizer->isAllowed($identity, 'article.edit'));
		self::assertTrue($authorizer->isAllowed($identity, 'article.delete'));
		self::assertTrue($authorizer->isAllowed($identity, 'article'));

		$builder->deny($role, 'article.edit');
		$builder->deny($role, 'article.delete');
		$authorizer = new PrivilegeAuthorizer($this->policies(), $builder->build());
		self::assertTrue($authorizer->hasPrivilege($identity, 'article.view'));
		self::assertFalse($authorizer->hasPrivilege($identity, 'article.edit'));
		self::assertFalse($authorizer->hasPrivilege($identity, 'article.delete'));
		self::assertFalse($authorizer->hasPrivilege($identity, 'article'));
		self::assertTrue($authorizer->isAllowed($identity, 'article.view'));
		self::assertFalse($authorizer->isAllowed($identity, 'article.edit'));
		self::assertFalse($authorizer->isAllowed($identity, 'article.delete'));
		self::assertFalse($authorizer->isAllowed($identity, 'article'));

		$builder->deny($role, 'article');
		$authorizer = new PrivilegeAuthorizer($this->policies(), $builder->build());
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
		$builder = new AuthorizationDataBuilder();
		$role = 'role';
		$identity = new IntIdentity(1, [$role]);

		$builder->addPrivilege('article.view');
		$builder->addPrivilege('article.edit');
		$builder->addPrivilege('article.delete');

		$builder->addRole($role);

		$builder->deny($role, 'article');
		$authorizer = new PrivilegeAuthorizer($this->policies(), $builder->build());
		self::assertFalse($authorizer->hasPrivilege($identity, 'article.view'));
		self::assertFalse($authorizer->hasPrivilege($identity, 'article.edit'));
		self::assertFalse($authorizer->hasPrivilege($identity, 'article.delete'));
		self::assertFalse($authorizer->hasPrivilege($identity, 'article'));
		self::assertFalse($authorizer->isAllowed($identity, 'article.view'));
		self::assertFalse($authorizer->isAllowed($identity, 'article.edit'));
		self::assertFalse($authorizer->isAllowed($identity, 'article.delete'));
		self::assertFalse($authorizer->isAllowed($identity, 'article'));

		$builder->allow($role, 'article.view');
		$builder->allow($role, 'article.edit');
		$authorizer = new PrivilegeAuthorizer($this->policies(), $builder->build());
		self::assertTrue($authorizer->hasPrivilege($identity, 'article.view'));
		self::assertTrue($authorizer->hasPrivilege($identity, 'article.edit'));
		self::assertFalse($authorizer->hasPrivilege($identity, 'article.delete'));
		self::assertFalse($authorizer->hasPrivilege($identity, 'article'));
		self::assertTrue($authorizer->isAllowed($identity, 'article.view'));
		self::assertTrue($authorizer->isAllowed($identity, 'article.edit'));
		self::assertFalse($authorizer->isAllowed($identity, 'article.delete'));
		self::assertFalse($authorizer->isAllowed($identity, 'article'));

		$builder->deny($role, 'article.edit');
		$builder->allow($role, 'article.delete');
		$authorizer = new PrivilegeAuthorizer($this->policies(), $builder->build());
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
		$builder = new AuthorizationDataBuilder();
		$role = 'role';
		$identity = new IntIdentity(1, [$role]);

		$builder->addPrivilege('article.view');
		$builder->addPrivilege('article.edit');
		$builder->addPrivilege('article.delete');

		$builder->addRole($role);

		$builder->allow($role, 'article.view');
		$builder->allow($role, 'article.edit');
		$authorizer = new PrivilegeAuthorizer($this->policies(), $builder->build());
		self::assertTrue($authorizer->hasPrivilege($identity, 'article.view'));
		self::assertTrue($authorizer->hasPrivilege($identity, 'article.edit'));
		self::assertFalse($authorizer->hasPrivilege($identity, 'article.delete'));
		self::assertFalse($authorizer->hasPrivilege($identity, 'article'));
		self::assertTrue($authorizer->isAllowed($identity, 'article.view'));
		self::assertTrue($authorizer->isAllowed($identity, 'article.edit'));
		self::assertFalse($authorizer->isAllowed($identity, 'article.delete'));
		self::assertFalse($authorizer->isAllowed($identity, 'article'));

		$builder->deny($role, 'article.edit');
		$authorizer = new PrivilegeAuthorizer($this->policies(), $builder->build());
		self::assertTrue($authorizer->hasPrivilege($identity, 'article.view'));
		self::assertFalse($authorizer->hasPrivilege($identity, 'article.edit'));
		self::assertFalse($authorizer->hasPrivilege($identity, 'article.delete'));
		self::assertFalse($authorizer->hasPrivilege($identity, 'article'));
		self::assertTrue($authorizer->isAllowed($identity, 'article.view'));
		self::assertFalse($authorizer->isAllowed($identity, 'article.edit'));
		self::assertFalse($authorizer->isAllowed($identity, 'article.delete'));
		self::assertFalse($authorizer->isAllowed($identity, 'article'));

		$builder->deny($role, 'article');
		$authorizer = new PrivilegeAuthorizer($this->policies(), $builder->build());
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
		$builder = new AuthorizationDataBuilder();
		$identity = new IntIdentity(1, ['unknown']);

		$builder->addRole('known');
		$builder->addPrivilege('something');
		$builder->allow('known', 'something');

		$authorizer = new PrivilegeAuthorizer($this->policies(), $builder->build());
		self::assertFalse($authorizer->hasPrivilege($identity, 'something'));
		self::assertFalse($authorizer->isAllowed($identity, 'something'));

		$identity = new IntIdentity(1, ['unknown', 'known']);
		self::assertTrue($authorizer->hasPrivilege($identity, 'something'));
		self::assertTrue($authorizer->isAllowed($identity, 'something'));
	}

	public function testIsAllowedWithPrivilegeChecksPrivilege(): void
	{
		$builder = new AuthorizationDataBuilder();
		$builder->addRole('role');

		$authorizer = new PrivilegeAuthorizer($this->policies(), $builder->build());
		$identity = new IntIdentity(1, ['role']);

		$this->expectException(UnknownPrivilege::class);
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

		$builder = new AuthorizationDataBuilder();

		$authorizer = new PrivilegeAuthorizer($policyManager, $builder->build());

		$this->expectException(UnknownPrivilege::class);
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
		$builder = new AuthorizationDataBuilder();
		$builder->addRole('role');

		$authorizer = new PrivilegeAuthorizer($this->policies(), $builder->build());
		$identity = new IntIdentity(1, ['role']);

		$this->expectException(UnknownPrivilege::class);
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
		$builder = new AuthorizationDataBuilder();

		$authorizer = new PrivilegeAuthorizer($this->policies(), $builder->build());

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

		$builder = new AuthorizationDataBuilder();
		$builder->addPrivilege(ArticleEditPolicy::getPrivilege());

		$authorizer = new PrivilegeAuthorizer($policyManager, $builder->build());

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

		$builder = new AuthorizationDataBuilder();
		$builder->addPrivilege(NoRequirementsPolicy::getPrivilege());

		$authorizer = new PrivilegeAuthorizer($policyManager, $builder->build());

		self::assertFalse($authorizer->isAllowed(new IntIdentity(1, []), NoRequirementsPolicy::getPrivilege(), null));
		self::assertFalse(
			$authorizer->isAllowed(new IntIdentity(1, []), NoRequirementsPolicy::getPrivilege(), new NoRequirements()),
		);
	}

	public function testPolicyNullableRequirementWithNull(): void
	{
		$policyManager = $this->policies();
		$policyManager->add(new NullableRequirementsPolicy());

		$builder = new AuthorizationDataBuilder();
		$builder->addPrivilege(NullableRequirementsPolicy::getPrivilege());

		$authorizer = new PrivilegeAuthorizer($policyManager, $builder->build());

		self::assertFalse(
			$authorizer->isAllowed(new IntIdentity(1, []), NullableRequirementsPolicy::getPrivilege(), null),
		);
	}

	public function testPolicyNonNullableRequirementWithNull(): void
	{
		$policyManager = $this->policies();
		$policyManager->add(new ArticleEditPolicy());

		$builder = new AuthorizationDataBuilder();
		$builder->addPrivilege(ArticleEditPolicy::getPrivilege());

		$authorizer = new PrivilegeAuthorizer($policyManager, $builder->build());

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

		$builder = new AuthorizationDataBuilder();

		$builder->addPrivilege('article.edit.all');
		$builder->addPrivilege('article.edit.owned');
		$builder->addPrivilege('article.view');
		$builder->addPrivilege(NeverPassPolicy::getPrivilege());

		$builder->addRole('owner');
		$builder->addRole('editor');
		$builder->addRole('supervisor');

		$builder->allow('editor', 'article.edit.all');
		$builder->allow('owner', 'article.edit.owned');
		$builder->allow('supervisor', Authorizer::ALL_PRIVILEGES);

		$authorizer = new PrivilegeAuthorizer($policyManager, $builder->build());

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
