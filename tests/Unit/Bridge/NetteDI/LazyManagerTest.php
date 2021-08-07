<?php declare(strict_types = 1);

namespace Tests\Orisai\Auth\Unit\Bridge\NetteDI;

use OriNette\DI\Boot\ManualConfigurator;
use OriNette\DI\Services\MissingService;
use Orisai\Auth\Bridge\NetteDI\LazyPolicyManager;
use Orisai\Exceptions\Logic\InvalidArgument;
use PHPUnit\Framework\TestCase;
use Tests\Orisai\Auth\Doubles\ArticleEditPolicy;
use function dirname;

final class LazyManagerTest extends TestCase
{

	public function test(): void
	{
		$configurator = new ManualConfigurator(dirname(__DIR__, 4));
		$configurator->setDebugMode(true);
		$configurator->addConfig(__DIR__ . '/config.manager.neon');

		$container = $configurator->createContainer();

		$manager = $container->getByType(LazyPolicyManager::class);

		self::assertInstanceOf(ArticleEditPolicy::class, $manager->get(ArticleEditPolicy::getPrivilege()));

		$e = null;
		try {
			$manager->get('invalid.class');
		} catch (MissingService $e) {
			// Handled below
		}

		self::assertInstanceOf(MissingService::class, $e);
		self::assertSame(
			$e->getMessage(),
			<<<'MSG'
Context: Service policy.invalid.class returns instance of stdClass.
Problem: Orisai\Auth\Bridge\NetteDI\LazyPolicyManager supports only instances of
         Orisai\Auth\Authorization\Policy.
Solution: Remove service from LazyPolicyManager or make the service return
          supported object type.
MSG,
		);

		$e = null;
		try {
			$manager->get('not.matching.privilege');
		} catch (InvalidArgument $e) {
			// Handled below
		}

		self::assertInstanceOf(InvalidArgument::class, $e);
		self::assertSame(
			$e->getMessage(),
			<<<'MSG'
Context: Class Tests\Orisai\Auth\Doubles\ArticleEditPolicy returns privilege
         article.edit.
Problem: It was expected to return not.matching.privilege.
Solution: Register service policy.article.edit to
          Orisai\Auth\Bridge\NetteDI\LazyPolicyManager with article.edit or
          change the privilege returned by class to not.matching.privilege.
MSG,
		);
	}

}
