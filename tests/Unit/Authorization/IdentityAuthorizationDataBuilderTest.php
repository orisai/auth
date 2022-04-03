<?php declare(strict_types = 1);

namespace Tests\Orisai\Auth\Unit\Authorization;

use Orisai\Auth\Authentication\IntIdentity;
use Orisai\Auth\Authorization\AuthorizationDataBuilder;
use Orisai\Auth\Authorization\Exception\UnknownPrivilege;
use Orisai\Auth\Authorization\IdentityAuthorizationDataBuilder;
use PHPUnit\Framework\TestCase;
use Throwable;

final class IdentityAuthorizationDataBuilderTest extends TestCase
{

	public function testEdenTittiesDataSeparated(): void
	{
		$builder = new AuthorizationDataBuilder();

		$builder->addPrivilege('article.view');
		$builder->addPrivilege('article.edit');
		$builder->addPrivilege('article.delete');

		$data = $builder->build();
		$identityBuilder = new IdentityAuthorizationDataBuilder($data);
		$identity = new IntIdentity(1, []);
		$identity2 = new IntIdentity(2, []);

		$identityData = $identityBuilder->build($identity);
		$identity2Data = $identityBuilder->build($identity2);

		self::assertSame(
			[],
			$identityData->getRawAllowedPrivileges(),
		);
		self::assertSame(
			[],
			$identity2Data->getRawAllowedPrivileges(),
		);

		$identityBuilder->allow($identity, 'article.view');
		$identityBuilder->allow($identity, 'article.edit');
		$identityBuilder->allow($identity2, 'article.delete');

		$identityData = $identityBuilder->build($identity);
		$identity2Data = $identityBuilder->build($identity2);

		self::assertSame(
			[
				'article' => [
					'view' => [],
					'edit' => [],
				],
			],
			$identityData->getRawAllowedPrivileges(),
		);
		self::assertSame(
			[
				'article' => [
					'delete' => [],
				],
			],
			$identity2Data->getRawAllowedPrivileges(),
		);
	}

	public function testRoot(): void
	{
		$builder = new AuthorizationDataBuilder();
		$data = $builder->build();
		$identityBuilder = new IdentityAuthorizationDataBuilder($data);

		$identity = new IntIdentity(1, []);
		$identityBuilder->addRoot($identity);
		$identityData = $identityBuilder->build($identity);
		self::assertTrue($identityData->isRoot());

		$identity2 = new IntIdentity(2, []);
		$identityBuilder->addRoot($identity2);
		$identityBuilder->removeRoot($identity2);
		$identity2Data = $identityBuilder->build($identity2);
		self::assertFalse($identity2Data->isRoot());
	}

	public function testAllowDenyA(): void
	{
		$builder = new AuthorizationDataBuilder();

		$builder->addPrivilege('article.view');
		$builder->addPrivilege('article.edit');
		$builder->addPrivilege('something');
		$data = $builder->build();

		$identityBuilder = new IdentityAuthorizationDataBuilder($data);
		$identity = new IntIdentity(1, []);

		$identityBuilder->allow($identity, 'article.view');
		$identityData = $identityBuilder->build($identity);

		self::assertSame(
			[
				'article' => [
					'view' => [],
				],
			],
			$identityData->getRawAllowedPrivileges(),
		);

		$identityBuilder->removeAllow($identity, 'article.view');
		$identityData = $identityBuilder->build($identity);

		self::assertSame(
			[],
			$identityData->getRawAllowedPrivileges(),
		);
	}

	public function testAllowDenyB(): void
	{
		$builder = new AuthorizationDataBuilder();

		$builder->addPrivilege('article.view');
		$builder->addPrivilege('article.edit');
		$builder->addPrivilege('something');
		$data = $builder->build();

		$identityBuilder = new IdentityAuthorizationDataBuilder($data);
		$identity = new IntIdentity(1, []);

		$identityBuilder->allow($identity, 'article.view');
		$identityBuilder->allow($identity, 'article.edit');
		$identityData = $identityBuilder->build($identity);

		self::assertSame(
			[
				'article' => [
					'view' => [],
					'edit' => [],
				],
			],
			$identityData->getRawAllowedPrivileges(),
		);

		$identityBuilder->removeAllow($identity, 'article.view');
		$identityData = $identityBuilder->build($identity);

		self::assertSame(
			[
				'article' => [
					'edit' => [],
				],
			],
			$identityData->getRawAllowedPrivileges(),
		);
	}

	public function testAllowDenyC(): void
	{
		$builder = new AuthorizationDataBuilder();

		$builder->addPrivilege('article.view');
		$builder->addPrivilege('article.edit');
		$builder->addPrivilege('something');
		$data = $builder->build();

		$identityBuilder = new IdentityAuthorizationDataBuilder($data);
		$identity = new IntIdentity(1, []);

		$identityBuilder->allow($identity, 'article');
		$identityData = $identityBuilder->build($identity);

		self::assertSame(
			[
				'article' => [
					'view' => [],
					'edit' => [],
				],
			],
			$identityData->getRawAllowedPrivileges(),
		);

		$identityBuilder->removeAllow($identity, 'article');
		$identityData = $identityBuilder->build($identity);

		self::assertSame(
			[],
			$identityData->getRawAllowedPrivileges(),
		);
	}

	public function testAllowChecksPrivilege(): void
	{
		$builder = new AuthorizationDataBuilder();
		$builder->addRole('role');
		$data = $builder->build();

		$identityBuilder = new IdentityAuthorizationDataBuilder($data);
		$identity = new IntIdentity(1, []);

		$e = null;
		try {
			$identityBuilder->allow($identity, 'unknown');
		} catch (UnknownPrivilege $e) {
			self::assertSame($e->getPrivilege(), 'unknown');
		}

		self::assertNotNull($e);
	}

	public function testDenyChecksPrivilege(): void
	{
		$builder = new AuthorizationDataBuilder();
		$builder->addRole('role');
		$data = $builder->build();

		$identityBuilder = new IdentityAuthorizationDataBuilder($data);
		$identity = new IntIdentity(1, []);

		$e = null;
		try {
			$identityBuilder->removeAllow($identity, 'unknown');
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
		$data = $builder->build();

		$identityBuilder = new IdentityAuthorizationDataBuilder($data);
		$identity = new IntIdentity(1, []);

		$exception = null;
		try {
			$identityBuilder->allow($identity, 'unknown');
			$identityBuilder->removeAllow($identity, 'unknown');
		} catch (Throwable $exception) {
			// Handled below
		}

		self::assertNull($exception);
	}

}
