<?php declare(strict_types = 1);

namespace Tests\Orisai\Auth\Unit\Authorization;

use Orisai\Auth\Authentication\IntIdentity;
use Orisai\Auth\Authorization\AccessEntry;
use Orisai\Auth\Authorization\AccessEntryType;
use Orisai\Auth\Authorization\AuthorizationDataBuilder;
use Orisai\Auth\Authorization\Exception\UnknownPrivilege;
use Orisai\Auth\Authorization\IdentityAuthorizationDataBuilder;
use Orisai\Auth\Authorization\NoRequirements;
use Orisai\Auth\Authorization\PrivilegeAuthorizer;
use Orisai\Auth\Authorization\SimpleAuthorizationDataCreator;
use Orisai\Auth\Authorization\SimplePolicyManager;
use Orisai\Exceptions\Logic\InvalidArgument;
use Orisai\TranslationContracts\TranslatableMessage;
use PHPUnit\Framework\TestCase;
use stdClass;
use Tests\Orisai\Auth\Doubles\AddAccessEntriesPolicy;
use Tests\Orisai\Auth\Doubles\AlwaysPassPolicy;
use Tests\Orisai\Auth\Doubles\Article;
use Tests\Orisai\Auth\Doubles\ArticleEditOwnedPolicy;
use Tests\Orisai\Auth\Doubles\ArticleEditPolicy;
use Tests\Orisai\Auth\Doubles\InconclusivePolicy;
use Tests\Orisai\Auth\Doubles\NeverPassPolicy;
use Tests\Orisai\Auth\Doubles\NoRequirementsPolicy;
use Tests\Orisai\Auth\Doubles\NoYieldPolicy;
use Tests\Orisai\Auth\Doubles\PassWithNoIdentityPolicy;
use Tests\Orisai\Auth\Doubles\PassWithNoRequirementsPolicy;
use Tests\Orisai\Auth\Doubles\User;

final class PrivilegeAuthorizerTest extends TestCase
{

	private function policies(): SimplePolicyManager
	{
		return new SimplePolicyManager();
	}

	public function testData(): void
	{
		$builder = new AuthorizationDataBuilder();
		$builder->addPrivilege('test');
		$authorizer = new PrivilegeAuthorizer($this->policies(), new SimpleAuthorizationDataCreator($builder));

		self::assertSame(['test'], $authorizer->getData()->getPrivileges());
	}

	public function testNothingSet(): void
	{
		$builder = new AuthorizationDataBuilder();

		$role = 'role';
		$builder->addRole($role);

		$builder->addPrivilege('article.view');
		$builder->addPrivilege('something');

		$authorizer = new PrivilegeAuthorizer($this->policies(), new SimpleAuthorizationDataCreator($builder));
		$identity = new IntIdentity(1, [$role]);

		self::assertFalse($authorizer->hasPrivilege($identity, 'article'));
		self::assertFalse($authorizer->hasPrivilege($identity, 'article.view'));
		self::assertFalse($authorizer->hasPrivilege($identity, 'something'));
		self::assertFalse($authorizer->isAllowed($identity, 'article'));
		self::assertFalse($authorizer->isAllowed($identity, 'article.view'));
		self::assertFalse($authorizer->isAllowed($identity, 'something'));
		self::assertFalse($authorizer->isRoot($identity));
	}

	public function testNoPrivileges(): void
	{
		$role = 'role';

		$builder = new AuthorizationDataBuilder();
		$builder->addRole($role);
		$builder->addPrivilege('something');

		$authorizer = new PrivilegeAuthorizer($this->policies(), new SimpleAuthorizationDataCreator($builder));
		$identity = new IntIdentity(1, [$role]);

		self::assertFalse($authorizer->hasPrivilege($identity, 'something'));
		self::assertFalse($authorizer->isAllowed($identity, 'something'));
		self::assertFalse($authorizer->isRoot($identity));
	}

	public function testAllAllowedForRoot(): void
	{
		$builder = new AuthorizationDataBuilder();

		$builder->addPrivilege('foo.bar.baz');
		$builder->addPrivilege('something.else');

		$builder->addRole('leeroy');

		$builder->addRoot('leeroy');

		$authorizer = new PrivilegeAuthorizer($this->policies(), new SimpleAuthorizationDataCreator($builder));
		$identity = new IntIdentity(1, ['leeroy']);

		self::assertTrue($authorizer->hasPrivilege($identity, 'foo'));
		self::assertTrue($authorizer->hasPrivilege($identity, 'foo.bar'));
		self::assertTrue($authorizer->hasPrivilege($identity, 'foo.bar.baz'));
		self::assertTrue($authorizer->hasPrivilege($identity, 'something.else'));
		self::assertTrue($authorizer->isAllowed($identity, 'foo'));
		self::assertTrue($authorizer->isAllowed($identity, 'foo.bar'));
		self::assertTrue($authorizer->isAllowed($identity, 'foo.bar.baz'));
		self::assertTrue($authorizer->isAllowed($identity, 'something.else'));
		self::assertTrue($authorizer->isRoot($identity));

		// Can't remove part of root privilege
		$builder->removeAllow('leeroy', 'foo.bar');
		$authorizer = new PrivilegeAuthorizer($this->policies(), new SimpleAuthorizationDataCreator($builder));

		self::assertTrue($authorizer->hasPrivilege($identity, 'foo'));
		self::assertTrue($authorizer->hasPrivilege($identity, 'foo.bar'));
		self::assertTrue($authorizer->hasPrivilege($identity, 'foo.bar.baz'));
		self::assertTrue($authorizer->hasPrivilege($identity, 'something.else'));
		self::assertTrue($authorizer->isAllowed($identity, 'foo'));
		self::assertTrue($authorizer->isAllowed($identity, 'foo.bar'));
		self::assertTrue($authorizer->isAllowed($identity, 'foo.bar.baz'));
		self::assertTrue($authorizer->isAllowed($identity, 'something.else'));
		self::assertTrue($authorizer->isRoot($identity));

		// Removing root is allowed
		$builder->removeRoot('leeroy');
		$authorizer = new PrivilegeAuthorizer($this->policies(), new SimpleAuthorizationDataCreator($builder));

		self::assertFalse($authorizer->hasPrivilege($identity, 'foo'));
		self::assertFalse($authorizer->hasPrivilege($identity, 'foo.bar'));
		self::assertFalse($authorizer->hasPrivilege($identity, 'foo.bar.baz'));
		self::assertFalse($authorizer->hasPrivilege($identity, 'something.else'));
		self::assertFalse($authorizer->isAllowed($identity, 'foo'));
		self::assertFalse($authorizer->isAllowed($identity, 'foo.bar'));
		self::assertFalse($authorizer->isAllowed($identity, 'foo.bar.baz'));
		self::assertFalse($authorizer->isAllowed($identity, 'something.else'));
		self::assertFalse($authorizer->isRoot($identity));
	}

	public function testAllAllowedExplicitly(): void
	{
		$builder = new AuthorizationDataBuilder();

		$builder->addPrivilege('foo.bar.baz');
		$builder->addPrivilege('something.else');

		$builder->addRole('garry');

		$builder->allow('garry', 'foo.bar.baz');
		$builder->allow('garry', 'something.else');

		$authorizer = new PrivilegeAuthorizer($this->policies(), new SimpleAuthorizationDataCreator($builder));
		$identity = new IntIdentity(1, ['garry']);

		self::assertTrue($authorizer->hasPrivilege($identity, 'foo'));
		self::assertTrue($authorizer->hasPrivilege($identity, 'foo.bar'));
		self::assertTrue($authorizer->hasPrivilege($identity, 'foo.bar.baz'));
		self::assertTrue($authorizer->hasPrivilege($identity, 'something.else'));
		self::assertTrue($authorizer->isAllowed($identity, 'foo'));
		self::assertTrue($authorizer->isAllowed($identity, 'foo.bar'));
		self::assertTrue($authorizer->isAllowed($identity, 'foo.bar.baz'));
		self::assertTrue($authorizer->isAllowed($identity, 'something.else'));
		self::assertFalse($authorizer->isRoot($identity));

		$builder->removeAllow('garry', 'foo.bar');
		$authorizer = new PrivilegeAuthorizer($this->policies(), new SimpleAuthorizationDataCreator($builder));

		self::assertFalse($authorizer->hasPrivilege($identity, 'foo'));
		self::assertFalse($authorizer->hasPrivilege($identity, 'foo.bar'));
		self::assertFalse($authorizer->hasPrivilege($identity, 'foo.bar.baz'));
		self::assertTrue($authorizer->hasPrivilege($identity, 'something.else'));
		self::assertFalse($authorizer->isAllowed($identity, 'foo'));
		self::assertFalse($authorizer->isAllowed($identity, 'foo.bar'));
		self::assertFalse($authorizer->isAllowed($identity, 'foo.bar.baz'));
		self::assertTrue($authorizer->isAllowed($identity, 'something.else'));
		self::assertFalse($authorizer->isRoot($identity));
	}

	public function testAllAllowedRolesNotMixed(): void
	{
		$builder = new AuthorizationDataBuilder();

		$builder->addPrivilege('foo');

		$builder->addRole('supervisor');
		$builder->addRole('admin');

		$builder->addRoot('supervisor');

		$authorizer = new PrivilegeAuthorizer($this->policies(), new SimpleAuthorizationDataCreator($builder));
		$supervisor = new IntIdentity(1, ['supervisor']);
		$admin = new IntIdentity(2, ['admin']);

		self::assertTrue($authorizer->hasPrivilege($supervisor, 'foo'));
		self::assertTrue($authorizer->isAllowed($supervisor, 'foo'));
		self::assertTrue($authorizer->isRoot($supervisor));

		self::assertFalse($authorizer->hasPrivilege($admin, 'foo'));
		self::assertFalse($authorizer->isAllowed($admin, 'foo'));
		self::assertFalse($authorizer->isRoot($admin));
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

		$authorizer = new PrivilegeAuthorizer($this->policies(), new SimpleAuthorizationDataCreator($builder));
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

	public function testPrivilegesFromIdentityAndRole(): void
	{
		$builder = new AuthorizationDataBuilder();

		$builder->addPrivilege('article.view');
		$builder->addPrivilege('article.edit.owned');
		$builder->addPrivilege('article.edit.all');
		$builder->addPrivilege('article.publish');
		$builder->addPrivilege('article.delete');

		$builder->addRole('editor');

		$builder->allow('editor', 'article.view');
		$builder->allow('editor', 'article.edit.owned');

		$identity = new IntIdentity(1, ['editor']);

		$authorizer = new PrivilegeAuthorizer($this->policies(), new SimpleAuthorizationDataCreator($builder));
		$data = $authorizer->getData();

		$identityBuilder = new IdentityAuthorizationDataBuilder($data);
		$identityBuilder->allow($identity, 'article.view');
		$identityBuilder->allow($identity, 'article.edit.all');
		$identityBuilder->allow($identity, 'article.publish');
		$identityBuilder->allow($identity, 'article.delete');

		$identityData = $identityBuilder->build($identity);
		$identity->setAuthorizationData($identityData);

		// requires privileges from role or identity
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

		// requires mix of privileges from both
		self::assertTrue($authorizer->hasPrivilege($identity, 'article.edit'));
		self::assertTrue($authorizer->hasPrivilege($identity, 'article'));
		self::assertTrue($authorizer->isAllowed($identity, 'article.edit'));
		self::assertTrue($authorizer->isAllowed($identity, 'article'));
	}

	public function testRootPrivilegeFromIdentity(): void
	{
		$builder = new AuthorizationDataBuilder();

		$builder->addPrivilege('article.view');
		$builder->addPrivilege('article.edit.owned');
		$builder->addPrivilege('article.edit.all');

		$authorizer = new PrivilegeAuthorizer($this->policies(), new SimpleAuthorizationDataCreator($builder));
		$data = $authorizer->getData();

		$identity = new IntIdentity(1, []);

		$identityBuilder = new IdentityAuthorizationDataBuilder($data);
		$identityBuilder->addRoot($identity);

		$identityData = $identityBuilder->build($identity);
		$identity->setAuthorizationData($identityData);

		self::assertTrue($authorizer->hasPrivilege($identity, 'article.view'));
		self::assertTrue($authorizer->hasPrivilege($identity, 'article.edit.owned'));
		self::assertTrue($authorizer->hasPrivilege($identity, 'article.edit.all'));
		self::assertTrue($authorizer->isAllowed($identity, 'article.view'));
		self::assertTrue($authorizer->isAllowed($identity, 'article.edit.owned'));
		self::assertTrue($authorizer->isAllowed($identity, 'article.edit.all'));
		self::assertTrue($authorizer->isRoot($identity));
	}

	public function testRolesNotMixed(): void
	{
		$builder = new AuthorizationDataBuilder();

		$builder->addPrivilege('foo');

		$builder->addRole('supervisor');
		$builder->addRole('admin');

		$builder->allow('supervisor', 'foo');

		$authorizer = new PrivilegeAuthorizer($this->policies(), new SimpleAuthorizationDataCreator($builder));
		$supervisor = new IntIdentity(1, ['supervisor']);
		$admin = new IntIdentity(2, ['admin']);

		self::assertTrue($authorizer->hasPrivilege($supervisor, 'foo'));
		self::assertTrue($authorizer->isAllowed($supervisor, 'foo'));
		self::assertFalse($authorizer->isRoot($supervisor));

		self::assertFalse($authorizer->hasPrivilege($admin, 'foo'));
		self::assertFalse($authorizer->isAllowed($admin, 'foo'));
		self::assertFalse($authorizer->isRoot($admin));
	}

	public function testActionsNotMixed(): void
	{
		$builder = new AuthorizationDataBuilder();

		$builder->addPrivilege('admin');
		$builder->addPrivilege('front');

		$role = 'guest';
		$builder->addRole($role);

		$identity = new IntIdentity(1, [$role]);

		$authorizer = new PrivilegeAuthorizer($this->policies(), new SimpleAuthorizationDataCreator($builder));

		self::assertFalse($authorizer->hasPrivilege($identity, 'front'));
		self::assertFalse($authorizer->hasPrivilege($identity, 'admin'));
		self::assertFalse($authorizer->isAllowed($identity, 'front'));
		self::assertFalse($authorizer->isAllowed($identity, 'admin'));

		$builder->allow($role, 'front');
		$authorizer = new PrivilegeAuthorizer($this->policies(), new SimpleAuthorizationDataCreator($builder));
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
		$authorizer = new PrivilegeAuthorizer($this->policies(), new SimpleAuthorizationDataCreator($builder));
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
		$authorizer = new PrivilegeAuthorizer($this->policies(), new SimpleAuthorizationDataCreator($builder));
		self::assertTrue($authorizer->hasPrivilege($identity, 'article.view'));
		self::assertTrue($authorizer->hasPrivilege($identity, 'article.edit'));
		self::assertTrue($authorizer->hasPrivilege($identity, 'article.delete'));
		self::assertTrue($authorizer->hasPrivilege($identity, 'article'));
		self::assertTrue($authorizer->isAllowed($identity, 'article.view'));
		self::assertTrue($authorizer->isAllowed($identity, 'article.edit'));
		self::assertTrue($authorizer->isAllowed($identity, 'article.delete'));
		self::assertTrue($authorizer->isAllowed($identity, 'article'));

		$builder->removeAllow($role, 'article.edit');
		$builder->removeAllow($role, 'article.delete');
		$authorizer = new PrivilegeAuthorizer($this->policies(), new SimpleAuthorizationDataCreator($builder));
		self::assertTrue($authorizer->hasPrivilege($identity, 'article.view'));
		self::assertFalse($authorizer->hasPrivilege($identity, 'article.edit'));
		self::assertFalse($authorizer->hasPrivilege($identity, 'article.delete'));
		self::assertFalse($authorizer->hasPrivilege($identity, 'article'));
		self::assertTrue($authorizer->isAllowed($identity, 'article.view'));
		self::assertFalse($authorizer->isAllowed($identity, 'article.edit'));
		self::assertFalse($authorizer->isAllowed($identity, 'article.delete'));
		self::assertFalse($authorizer->isAllowed($identity, 'article'));

		$builder->removeAllow($role, 'article');
		$authorizer = new PrivilegeAuthorizer($this->policies(), new SimpleAuthorizationDataCreator($builder));
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

		$builder->removeAllow($role, 'article');
		$authorizer = new PrivilegeAuthorizer($this->policies(), new SimpleAuthorizationDataCreator($builder));
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
		$authorizer = new PrivilegeAuthorizer($this->policies(), new SimpleAuthorizationDataCreator($builder));
		self::assertTrue($authorizer->hasPrivilege($identity, 'article.view'));
		self::assertTrue($authorizer->hasPrivilege($identity, 'article.edit'));
		self::assertFalse($authorizer->hasPrivilege($identity, 'article.delete'));
		self::assertFalse($authorizer->hasPrivilege($identity, 'article'));
		self::assertTrue($authorizer->isAllowed($identity, 'article.view'));
		self::assertTrue($authorizer->isAllowed($identity, 'article.edit'));
		self::assertFalse($authorizer->isAllowed($identity, 'article.delete'));
		self::assertFalse($authorizer->isAllowed($identity, 'article'));

		$builder->removeAllow($role, 'article.edit');
		$builder->allow($role, 'article.delete');
		$authorizer = new PrivilegeAuthorizer($this->policies(), new SimpleAuthorizationDataCreator($builder));
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
		$authorizer = new PrivilegeAuthorizer($this->policies(), new SimpleAuthorizationDataCreator($builder));
		self::assertTrue($authorizer->hasPrivilege($identity, 'article.view'));
		self::assertTrue($authorizer->hasPrivilege($identity, 'article.edit'));
		self::assertFalse($authorizer->hasPrivilege($identity, 'article.delete'));
		self::assertFalse($authorizer->hasPrivilege($identity, 'article'));
		self::assertTrue($authorizer->isAllowed($identity, 'article.view'));
		self::assertTrue($authorizer->isAllowed($identity, 'article.edit'));
		self::assertFalse($authorizer->isAllowed($identity, 'article.delete'));
		self::assertFalse($authorizer->isAllowed($identity, 'article'));

		$builder->removeAllow($role, 'article.edit');
		$authorizer = new PrivilegeAuthorizer($this->policies(), new SimpleAuthorizationDataCreator($builder));
		self::assertTrue($authorizer->hasPrivilege($identity, 'article.view'));
		self::assertFalse($authorizer->hasPrivilege($identity, 'article.edit'));
		self::assertFalse($authorizer->hasPrivilege($identity, 'article.delete'));
		self::assertFalse($authorizer->hasPrivilege($identity, 'article'));
		self::assertTrue($authorizer->isAllowed($identity, 'article.view'));
		self::assertFalse($authorizer->isAllowed($identity, 'article.edit'));
		self::assertFalse($authorizer->isAllowed($identity, 'article.delete'));
		self::assertFalse($authorizer->isAllowed($identity, 'article'));

		$builder->removeAllow($role, 'article');
		$authorizer = new PrivilegeAuthorizer($this->policies(), new SimpleAuthorizationDataCreator($builder));
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
		$authorizer = new PrivilegeAuthorizer($this->policies(), new SimpleAuthorizationDataCreator($builder));

		self::assertFalse($authorizer->hasPrivilege($identity, 'something'));
		self::assertFalse($authorizer->isAllowed($identity, 'something'));

		$identity = new IntIdentity(1, ['unknown', 'known']);
		self::assertTrue($authorizer->hasPrivilege($identity, 'something'));
		self::assertTrue($authorizer->isAllowed($identity, 'something'));
	}

	public function testSkipUnknownRolesForRoot(): void
	{
		$builder = new AuthorizationDataBuilder();
		$builder->addRole('known');
		$builder->addRoot('known');
		$builder->addPrivilege('something');

		$authorizer = new PrivilegeAuthorizer($this->policies(), new SimpleAuthorizationDataCreator($builder));

		$identity = new IntIdentity(1, ['unknown']);
		self::assertFalse($authorizer->hasPrivilege($identity, 'something'));
		self::assertFalse($authorizer->isAllowed($identity, 'something'));
		self::assertFalse($authorizer->isRoot($identity));

		$identity = new IntIdentity(1, ['unknown', 'known']);
		self::assertTrue($authorizer->hasPrivilege($identity, 'something'));
		self::assertTrue($authorizer->isAllowed($identity, 'something'));
		self::assertTrue($authorizer->isRoot($identity));
	}

	public function testIsAllowedWithPrivilegeChecksPrivilege(): void
	{
		$builder = new AuthorizationDataBuilder();
		$builder->addRole('role');

		$authorizer = new PrivilegeAuthorizer($this->policies(), new SimpleAuthorizationDataCreator($builder));
		$identity = new IntIdentity(1, ['role']);

		$e = null;
		try {
			$authorizer->isAllowed($identity, 'unknown');
		} catch (UnknownPrivilege $e) {
			self::assertSame($e->getPrivilege(), 'unknown');
		}

		self::assertNotNull($e);
	}

	public function testIsAllowedWithPolicyChecksPrivilege(): void
	{
		$policyManager = $this->policies();
		$policyManager->add(new ArticleEditPolicy());

		$builder = new AuthorizationDataBuilder();

		$authorizer = new PrivilegeAuthorizer($policyManager, new SimpleAuthorizationDataCreator($builder));

		$e = null;
		try {
			$authorizer->isAllowed(new IntIdentity(1, []), ArticleEditPolicy::getPrivilege());
		} catch (UnknownPrivilege $e) {
			self::assertSame($e->getPrivilege(), ArticleEditPolicy::getPrivilege());
		}

		self::assertNotNull($e);
	}

	public function testHasPrivilegeChecksPrivilege(): void
	{
		$builder = new AuthorizationDataBuilder();
		$builder->addRole('role');

		$authorizer = new PrivilegeAuthorizer($this->policies(), new SimpleAuthorizationDataCreator($builder));
		$identity = new IntIdentity(1, ['role']);

		$e = null;
		try {
			$authorizer->hasPrivilege($identity, 'unknown');
		} catch (UnknownPrivilege $e) {
			self::assertSame($e->getPrivilege(), 'unknown');
		}

		self::assertNotNull($e);
	}

	public function testIsAllowedWithoutPolicyForbidsRequirements(): void
	{
		$builder = new AuthorizationDataBuilder();

		$authorizer = new PrivilegeAuthorizer($this->policies(), new SimpleAuthorizationDataCreator($builder));

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

		$authorizer = new PrivilegeAuthorizer($policyManager, new SimpleAuthorizationDataCreator($builder));

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

		$authorizer = new PrivilegeAuthorizer($policyManager, new SimpleAuthorizationDataCreator($builder));

		self::assertTrue($authorizer->isAllowed(new IntIdentity(1, []), NoRequirementsPolicy::getPrivilege(), null));
		self::assertTrue(
			$authorizer->isAllowed(new IntIdentity(1, []), NoRequirementsPolicy::getPrivilege(), new NoRequirements()),
		);
	}

	public function testPolicyNullableRequirementWithNull(): void
	{
		$policyManager = $this->policies();
		$policyManager->add(new PassWithNoRequirementsPolicy());

		$builder = new AuthorizationDataBuilder();
		$builder->addPrivilege(PassWithNoRequirementsPolicy::getPrivilege());

		$authorizer = new PrivilegeAuthorizer($policyManager, new SimpleAuthorizationDataCreator($builder));

		self::assertTrue(
			$authorizer->isAllowed(new IntIdentity(1, []), PassWithNoRequirementsPolicy::getPrivilege(), null),
		);
	}

	public function testPolicyNonNullableRequirementWithNull(): void
	{
		$policyManager = $this->policies();
		$policyManager->add(new ArticleEditPolicy());

		$builder = new AuthorizationDataBuilder();
		$builder->addPrivilege(ArticleEditPolicy::getPrivilege());

		$authorizer = new PrivilegeAuthorizer($policyManager, new SimpleAuthorizationDataCreator($builder));

		$this->expectException(InvalidArgument::class);
		$this->expectExceptionMessage(<<<'MSG'
Context: Trying to check privilege article.edit via
         Orisai\Auth\Authorization\PrivilegeAuthorizer->isAllowed().
Problem: Policy requirements are missing, which is not supported by
         Tests\Orisai\Auth\Doubles\ArticleEditPolicy.
Solution: Pass requirements of type Tests\Orisai\Auth\Doubles\Article or
          implement Orisai\Auth\Authorization\OptionalRequirementsPolicy or
          change them to Orisai\Auth\Authorization\NoRequirements.
MSG);

		$authorizer->isAllowed(new IntIdentity(1, []), ArticleEditPolicy::getPrivilege(), null);
	}

	public function testPolicyNullableIdentity(): void
	{
		$policyManager = $this->policies();
		$policyManager->add(new PassWithNoIdentityPolicy());

		$builder = new AuthorizationDataBuilder();
		$builder->addPrivilege(PassWithNoIdentityPolicy::getPrivilege());

		$authorizer = new PrivilegeAuthorizer($policyManager, new SimpleAuthorizationDataCreator($builder));

		self::assertFalse(
			$authorizer->isAllowed(new IntIdentity(1, []), PassWithNoIdentityPolicy::getPrivilege()),
		);
		self::assertTrue(
			$authorizer->isAllowed(null, PassWithNoIdentityPolicy::getPrivilege()),
		);
	}

	public function testPolicyAccessEntries(): void
	{
		$policyManager = $this->policies();
		$policyManager->add(new NoRequirementsPolicy());
		$policyManager->add(new AddAccessEntriesPolicy());

		$builder = new AuthorizationDataBuilder();
		$builder->addPrivilege(NoRequirementsPolicy::getPrivilege());
		$builder->addPrivilege(AddAccessEntriesPolicy::getPrivilege());

		$authorizer = new PrivilegeAuthorizer($policyManager, new SimpleAuthorizationDataCreator($builder));

		$identity = new IntIdentity(1, []);

		$allowed = $authorizer->isAllowed($identity, NoRequirementsPolicy::getPrivilege(), null, $entries);
		self::assertTrue($allowed);
		self::assertEquals(
			[
				new AccessEntry(
					AccessEntryType::allowed(),
					'',
				),
			],
			$entries,
		);

		$allowed = $authorizer->isAllowed($identity, AddAccessEntriesPolicy::getPrivilege(), null, $entries);
		self::assertTrue($allowed);
		self::assertEquals(
			[
				new AccessEntry(
					AccessEntryType::allowed(),
					'Message',
				),
				new AccessEntry(
					AccessEntryType::allowed(),
					new TranslatableMessage('message.id'),
				),
			],
			$entries,
		);
	}

	public function testNeverPassPolicy(): void
	{
		$policyManager = $this->policies();
		$policyManager->add(new NeverPassPolicy());

		$builder = new AuthorizationDataBuilder();
		$builder->addPrivilege(NeverPassPolicy::getPrivilege());

		$authorizer = new PrivilegeAuthorizer($policyManager, new SimpleAuthorizationDataCreator($builder));

		$identity = new IntIdentity(1, []);

		$allowed = $authorizer->isAllowed($identity, NeverPassPolicy::getPrivilege(), null, $entries);
		self::assertFalse($allowed);
		self::assertEquals(
			[
				new AccessEntry(
					AccessEntryType::forbidden(),
					'',
				),
				new AccessEntry(
					AccessEntryType::forbidden(),
					'',
				),
			],
			$entries,
		);
	}

	public function testAlwaysPassPolicy(): void
	{
		$policyManager = $this->policies();
		$policyManager->add(new AlwaysPassPolicy());

		$builder = new AuthorizationDataBuilder();
		$builder->addPrivilege(AlwaysPassPolicy::getPrivilege());

		$authorizer = new PrivilegeAuthorizer($policyManager, new SimpleAuthorizationDataCreator($builder));

		$identity = new IntIdentity(1, []);

		$allowed = $authorizer->isAllowed($identity, AlwaysPassPolicy::getPrivilege(), null, $entries);
		self::assertTrue($allowed);
		self::assertEquals(
			[
				new AccessEntry(
					AccessEntryType::allowed(),
					'',
				),
				new AccessEntry(
					AccessEntryType::allowed(),
					'',
				),
			],
			$entries,
		);
	}

	public function testInconclusivePolicy(): void
	{
		$policyManager = $this->policies();
		$policyManager->add(new InconclusivePolicy());

		$builder = new AuthorizationDataBuilder();
		$builder->addPrivilege(InconclusivePolicy::getPrivilege());

		$authorizer = new PrivilegeAuthorizer($policyManager, new SimpleAuthorizationDataCreator($builder));

		$identity = new IntIdentity(1, []);

		$allowed = $authorizer->isAllowed($identity, InconclusivePolicy::getPrivilege(), null, $entries);
		self::assertFalse($allowed);
		self::assertEquals(
			[
				new AccessEntry(
					AccessEntryType::skipped(),
					'',
				),
				new AccessEntry(
					AccessEntryType::allowed(),
					'',
				),
			],
			$entries,
		);
	}

	public function testNoYieldPolicy(): void
	{
		$policyManager = $this->policies();
		$policyManager->add(new NoYieldPolicy());

		$builder = new AuthorizationDataBuilder();
		$builder->addPrivilege(NoYieldPolicy::getPrivilege());

		$authorizer = new PrivilegeAuthorizer($policyManager, new SimpleAuthorizationDataCreator($builder));

		$identity = new IntIdentity(1, []);

		$this->expectException(InvalidArgument::class);
		$this->expectExceptionMessage(
			<<<'MSG'
Context: Checking policy 'Tests\Orisai\Auth\Doubles\NoYieldPolicy'.
Problem: Policy yielded no 'Orisai\Auth\Authorization\AccessEntry'.
Solution: Yield at least one entry.
MSG,
		);

		$authorizer->isAllowed($identity, NoYieldPolicy::getPrivilege());
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
		$builder->addRoot('supervisor');

		$authorizer = new PrivilegeAuthorizer($policyManager, new SimpleAuthorizationDataCreator($builder));

		$user1 = new User(1);
		$article1 = new Article($user1);

		// Don't have privileges
		$identity1 = new IntIdentity($user1->getId(), []);

		self::assertFalse($authorizer->isAllowed($identity1, ArticleEditPolicy::getPrivilege(), $article1));
		self::assertFalse($authorizer->isAllowed($identity1, ArticleEditOwnedPolicy::getPrivilege(), $article1));

		// Has access to owned resources
		$identity1 = new IntIdentity($user1->getId(), ['owner']);

		self::assertTrue($authorizer->hasPrivilege($identity1, 'article.edit.owned'));
		self::assertTrue($authorizer->isAllowed($identity1, ArticleEditPolicy::getPrivilege(), $article1));
		self::assertTrue($authorizer->isAllowed($identity1, ArticleEditOwnedPolicy::getPrivilege(), $article1));

		// Does not have access to resource of another user
		$user2 = new User(2);
		$identity2 = new IntIdentity($user2->getId(), ['owner']);
		self::assertTrue($authorizer->hasPrivilege($identity2, 'article.edit.owned'));
		self::assertFalse($authorizer->isAllowed($identity2, ArticleEditPolicy::getPrivilege(), $article1));

		// Has access to resources of all users
		$identity1 = new IntIdentity($user1->getId(), ['owner', 'editor']);
		$article2 = new Article($user2);
		self::assertTrue($authorizer->isAllowed($identity1, ArticleEditPolicy::getPrivilege(), $article2));

		// - but not other resources
		self::assertFalse($authorizer->isAllowed($identity1, 'article.view'));
		self::assertFalse($authorizer->isAllowed($identity1, 'article'));
		self::assertFalse($authorizer->isRoot($identity1));

		// Has access to all resources as a root
		$identity1 = new IntIdentity($user1->getId(), ['supervisor']);

		self::assertTrue($authorizer->isAllowed($identity1, ArticleEditPolicy::getPrivilege(), $article2));

		self::assertTrue($authorizer->isAllowed($identity1, 'article.view'));
		self::assertTrue($authorizer->isAllowed($identity1, 'article'));
		self::assertTrue($authorizer->isRoot($identity1));

		// - including these with policy which does not allow it
		self::assertTrue($authorizer->hasPrivilege($identity1, NeverPassPolicy::getPrivilege()));
	}

}
