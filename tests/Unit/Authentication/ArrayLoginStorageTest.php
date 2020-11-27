<?php declare(strict_types = 1);

namespace Tests\Orisai\Auth\Unit\Authentication;

use Orisai\Auth\Authentication\ArrayLoginStorage;
use Orisai\Auth\Authentication\LoginStorage;
use PHPUnit\Framework\TestCase;

final class ArrayLoginStorageTest extends TestCase
{

	private function createStorage(): LoginStorage
	{
		return new ArrayLoginStorage();
	}

	public function test(): void
	{
		$storage = $this->createStorage();

		self::assertFalse($storage->alreadyExists('front'));
		$loginsFront = $storage->getLogins('front');
		self::assertNull($loginsFront->getCurrentLogin());
		self::assertSame([], $loginsFront->getExpiredLogins());
		self::assertTrue($storage->alreadyExists('front'));

		self::assertFalse($storage->alreadyExists('admin'));
		$loginsAdmin = $storage->getLogins('admin');
		self::assertNotSame($loginsAdmin, $loginsFront);
		self::assertEquals($loginsAdmin, $loginsFront);
		self::assertTrue($storage->alreadyExists('admin'));

		$storage->regenerateSecurityToken('doesnt matter');
	}

}
