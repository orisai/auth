<?php declare(strict_types = 1);

namespace Tests\Orisai\Auth\Unit\Bridge\NetteDI;

use OriNette\DI\Boot\ManualConfigurator;
use PHPUnit\Framework\TestCase;
use Tests\Orisai\Auth\Doubles\TestingFirewall;
use function dirname;

final class NetteDISetupTest extends TestCase
{

	public function test(): void
	{
		$configurator = new ManualConfigurator(dirname(__DIR__, 4));
		$configurator->setDebugMode(true);
		$configurator->addConfig(__DIR__ . '/config.neon');

		$container = $configurator->createContainer();

		self::assertInstanceOf(TestingFirewall::class, $container->getService('auth.api.firewall'));
		self::assertInstanceOf(TestingFirewall::class, $container->getService('auth.admin.firewall'));
		self::assertInstanceOf(TestingFirewall::class, $container->getService('auth.front.firewall'));
	}

}
