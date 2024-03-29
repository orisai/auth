<?php declare(strict_types = 1);

namespace Tests\Orisai\Auth\Unit\Authentication\Data;

use DateTimeImmutable;
use Orisai\Auth\Authentication\Data\CurrentExpiration;
use Orisai\Auth\Authentication\Data\CurrentLogin;
use Orisai\Auth\Authentication\Data\Expiration;
use Orisai\Auth\Authentication\Data\ExpiredLogin;
use Orisai\Auth\Authentication\IntIdentity;
use Orisai\Auth\Authentication\LogoutCode;
use Orisai\TranslationContracts\TranslatableMessage;
use PHPUnit\Framework\TestCase;
use function assert;
use function serialize;
use function unserialize;

final class ExpiredLoginTest extends TestCase
{

	public function testBase(): void
	{
		$identity = new IntIdentity(1, []);
		$authTime = DateTimeImmutable::createFromFormat('U', '2');
		$currentLogin = new CurrentLogin($identity, $authTime);
		$login = new ExpiredLogin($currentLogin, LogoutCode::manual());

		self::assertSame($identity, $login->getIdentity());
		self::assertSame($authTime, $login->getAuthenticationTime());
		self::assertNull($login->getExpiration());
		self::assertEquals(LogoutCode::manual(), $login->getLogoutCode());
		self::assertNull($login->getLogoutReason());

		self::assertEquals($login, unserialize(serialize($login)));

		$login = new ExpiredLogin($currentLogin, LogoutCode::manual(), 'description');
		self::assertSame('description', $login->getLogoutReason());
		self::assertEquals($login, unserialize(serialize($login)));

		$reason = new TranslatableMessage('description');
		$login = new ExpiredLogin($currentLogin, LogoutCode::manual(), $reason);
		self::assertSame($reason, $login->getLogoutReason());
		self::assertEquals($login, unserialize(serialize($login)));
	}

	public function testExpiration(): void
	{
		$identity = new IntIdentity(1, []);
		$currentLogin = new CurrentLogin($identity, DateTimeImmutable::createFromFormat('U', '2'));
		$time = DateTimeImmutable::createFromFormat('U', '123');
		$delta = 456;
		$currentLogin->setExpiration(new CurrentExpiration($time, $delta));
		$login = new ExpiredLogin($currentLogin, LogoutCode::manual());

		$expiration = $login->getExpiration();
		self::assertInstanceOf(Expiration::class, $expiration);
		self::assertSame($time, $expiration->getTime());
		self::assertSame($delta, $expiration->getDelta());

		self::assertEquals($login, unserialize(serialize($login)));
	}

	public function testIncompleteIdentityClass(): void
	{
		// phpcs:ignore SlevomatCodingStandard.Files.LineLength.LineTooLong
		$serialized = 'O:44:"Orisai\Auth\Authentication\Data\ExpiredLogin":4:{s:8:"identity";O:15:"InvalidIdentity":2:{s:2:"id";i:1;s:5:"roles";a:0:{}}s:18:"authenticationTime";i:2;s:12:"logoutReason";i:1;s:10:"expiration";O:42:"Orisai\Auth\Authentication\Data\Expiration":2:{s:4:"time";i:123;s:5:"delta";i:456;}}';

		$login = unserialize($serialized);
		assert($login instanceof ExpiredLogin);

		self::assertTrue($login->hasInvalidIdentity());
	}

	public function testSerializationBC(): void
	{
		// phpcs:ignore SlevomatCodingStandard.Files.LineLength.LineTooLong
		$serialized = 'O:44:"Orisai\Auth\Authentication\Data\ExpiredLogin":4:{s:8:"identity";O:38:"Orisai\Auth\Authentication\IntIdentity":3:{s:5:"roles";a:0:{}s:8:"authData";N;s:2:"id";i:1;}s:18:"authenticationTime";i:2;s:12:"logoutReason";i:1;s:10:"expiration";N;}';
		$login = unserialize($serialized);

		self::assertInstanceOf(ExpiredLogin::class, $login);
		self::assertSame(2, $login->getAuthenticationTime()->getTimestamp());
		self::assertInstanceOf(IntIdentity::class, $login->getIdentity());
		self::assertNull($login->getExpiration());
		self::assertEquals(LogoutCode::manual(), $login->getLogoutCode());
		self::assertNull($login->getLogoutReason());

		// phpcs:ignore SlevomatCodingStandard.Files.LineLength.LineTooLong
		$serialized = 'O:44:"Orisai\Auth\Authentication\Data\ExpiredLogin":5:{s:8:"identity";O:38:"Orisai\Auth\Authentication\IntIdentity":3:{s:5:"roles";a:0:{}s:8:"authData";N;s:2:"id";i:1;}s:18:"authenticationTime";i:2;s:12:"logoutReason";i:1;s:23:"logoutReasonDescription";s:6:"reason";s:10:"expiration";O:42:"Orisai\Auth\Authentication\Data\Expiration":2:{s:4:"time";i:123;s:5:"delta";i:456;}}"string(374) "O:44:"Orisai\Auth\Authentication\Data\ExpiredLogin":5:{s:8:"identity";O:38:"Orisai\Auth\Authentication\IntIdentity":3:{s:5:"roles";a:0:{}s:8:"authData";N;s:2:"id";i:1;}s:18:"authenticationTime";i:2;s:12:"logoutReason";i:1;s:23:"logoutReasonDescription";s:6:"reason";s:10:"expiration";O:42:"Orisai\Auth\Authentication\Data\Expiration":2:{s:4:"time";i:123;s:5:"delta";i:456;}}';
		$login = unserialize($serialized);

		self::assertInstanceOf(ExpiredLogin::class, $login);
		$expiration = $login->getExpiration();
		self::assertInstanceOf(Expiration::class, $expiration);
		self::assertSame(123, $expiration->getTime()->getTimestamp());
		self::assertSame(456, $expiration->getDelta());
		$reason = $login->getLogoutReason();
		self::assertSame('reason', $reason);

		// phpcs:ignore SlevomatCodingStandard.Files.LineLength.LineTooLong
		$serialized = 'O:44:"Orisai\Auth\Authentication\Data\ExpiredLogin":5:{s:8:"identity";O:38:"Orisai\Auth\Authentication\IntIdentity":3:{s:5:"roles";a:0:{}s:8:"authData";N;s:2:"id";i:1;}s:18:"authenticationTime";i:2;s:12:"logoutReason";i:1;s:23:"logoutReasonDescription";O:41:"Orisai\Auth\Authentication\DecisionReason":3:{s:7:"message";s:7:"message";s:10:"parameters";a:0:{}s:12:"translatable";b:1;}s:10:"expiration";N;}"string(403) "O:44:"Orisai\Auth\Authentication\Data\ExpiredLogin":5:{s:8:"identity";O:38:"Orisai\Auth\Authentication\IntIdentity":3:{s:5:"roles";a:0:{}s:8:"authData";N;s:2:"id";i:1;}s:18:"authenticationTime";i:2;s:12:"logoutReason";i:1;s:23:"logoutReasonDescription";O:41:"Orisai\Auth\Authentication\DecisionReason":3:{s:7:"message";s:7:"message";s:10:"parameters";a:0:{}s:12:"translatable";b:1;}s:10:"expiration";N;}';
		$login = unserialize($serialized);

		self::assertInstanceOf(ExpiredLogin::class, $login);
		$reason = $login->getLogoutReason();
		self::assertEquals(new TranslatableMessage('message'), $reason);

		// phpcs:ignore SlevomatCodingStandard.Files.LineLength.LineTooLong
		$serialized = 'O:44:"Orisai\Auth\Authentication\Data\ExpiredLogin":5:{s:8:"identity";O:38:"Orisai\Auth\Authentication\IntIdentity":3:{s:5:"roles";a:0:{}s:8:"authData";N;s:2:"id";i:123;}s:18:"authenticationTime";i:123;s:12:"logoutReason";i:1;s:23:"logoutReasonDescription";O:41:"Orisai\Auth\Authentication\DecisionReason":3:{s:7:"message";s:6:"reason";s:10:"parameters";a:0:{}s:12:"translatable";b:0;}s:10:"expiration";N;}';
		$login = unserialize($serialized);

		self::assertInstanceOf(ExpiredLogin::class, $login);
		self::assertEquals('reason', $login->getLogoutReason());
	}

}
