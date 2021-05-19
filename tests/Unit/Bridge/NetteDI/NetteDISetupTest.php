<?php declare(strict_types = 1);

namespace Tests\Orisai\Auth\Unit\Bridge\NetteDI;

use OriNette\DI\Boot\ManualConfigurator;
use Orisai\Auth\Authentication\Firewall;
use Orisai\Auth\Authentication\IntIdentity;
use PHPUnit\Framework\TestCase;
use Tests\Orisai\Auth\Doubles\Article;
use Tests\Orisai\Auth\Doubles\ArticleEditPolicy;
use Tests\Orisai\Auth\Doubles\TestingFirewall;
use Tests\Orisai\Auth\Doubles\User;
use function assert;
use function dirname;

final class NetteDISetupTest extends TestCase
{

	public function testBuild(): void
	{
		$configurator = new ManualConfigurator(dirname(__DIR__, 4));
		$configurator->setDebugMode(true);
		$configurator->addConfig(__DIR__ . '/config.full.neon');

		$container = $configurator->createContainer();

		self::assertInstanceOf(TestingFirewall::class, $container->getService('auth.api.firewall'));
		self::assertInstanceOf(TestingFirewall::class, $container->getService('auth.admin.firewall'));
		self::assertInstanceOf(TestingFirewall::class, $container->getService('auth.front.firewall'));
	}

	/**
	 * @runInSeparateProcess
	 */
	public function testPolicy(): void
	{
		$configurator = new ManualConfigurator(dirname(__DIR__, 4));
		$configurator->setDebugMode(true);
		$configurator->addConfig(__DIR__ . '/config.full.neon');

		$container = $configurator->createContainer();

		$firewall = $container->getService('auth.front.firewall');
		assert($firewall instanceof Firewall);

		$firewall->login(new IntIdentity(1, ['editor']));
		self::assertTrue($firewall->isAllowed(...ArticleEditPolicy::get(new Article(new User(1)))));
		self::assertTrue($firewall->isAllowed(...ArticleEditPolicy::get(new Article(new User(2)))));
	}

}
