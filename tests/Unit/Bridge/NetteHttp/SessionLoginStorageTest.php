<?php declare(strict_types = 1);

namespace Tests\Orisai\Auth\Unit\Bridge\NetteHttp;

use Nette\Http\Request;
use Nette\Http\Response;
use Nette\Http\Session;
use Nette\Http\UrlScript;
use Orisai\Auth\Authentication\LoginStorage;
use Orisai\Auth\Bridge\NetteHttp\SessionLoginStorage;
use PHPUnit\Framework\TestCase;

/**
 * @runTestsInSeparateProcesses
 */
final class SessionLoginStorageTest extends TestCase
{

	private function createSession(): Session
	{
		return new Session(new Request(new UrlScript('https://example.com')), new Response());
	}

	private function createStorage(Session $session): LoginStorage
	{
		return new SessionLoginStorage($session);
	}

	public function test(): void
	{
		$session = $this->createSession();
		$storage = $this->createStorage($session);

		self::assertFalse($storage->alreadyExists('front'));
		self::assertFalse($session->hasSection('orisai.auth.front'));
		$loginsFront = $storage->getLogins('front');
		self::assertNull($loginsFront->getCurrentLogin());
		self::assertSame([], $loginsFront->getExpiredLogins());
		self::assertTrue($storage->alreadyExists('front'));
		self::assertTrue($session->hasSection('orisai.auth.front'));

		$sessionId = $session->getId();

		self::assertFalse($storage->alreadyExists('admin'));
		self::assertFalse($session->hasSection('orisai.auth.admin'));
		$loginsAdmin = $storage->getLogins('admin');
		self::assertNotSame($loginsAdmin, $loginsFront);
		self::assertEquals($loginsAdmin, $loginsFront);
		self::assertTrue($storage->alreadyExists('admin'));
		self::assertTrue($session->hasSection('orisai.auth.admin'));

		$storage->regenerateSecurityToken('doesnt matter');
		self::assertNotSame($sessionId, $session->getId());
	}

	public function testUseExistingSession(): void
	{
		$session = $this->createSession();

		$storage = $this->createStorage($session);
		$logins = $storage->getLogins('test');
		self::assertSame($logins, $storage->getLogins('test'));

		$storage = $this->createStorage($session);
		self::assertSame($logins, $storage->getLogins('test'));
	}

}
