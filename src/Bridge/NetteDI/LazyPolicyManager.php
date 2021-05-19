<?php declare(strict_types = 1);

namespace Orisai\Auth\Bridge\NetteDI;

use Nette\DI\Container;
use Orisai\Auth\Authorization\Policy;
use Orisai\Auth\Authorization\PolicyManager;
use Orisai\Exceptions\Logic\InvalidArgument;
use Orisai\Exceptions\Message;
use function array_pop;
use function explode;
use function get_class;

final class LazyPolicyManager implements PolicyManager
{

	/** @var array<string, string> */
	private array $servicesMap;

	private Container $container;

	/**
	 * @param array<string, string> $servicesMap
	 */
	public function __construct(array $servicesMap, Container $container)
	{
		$this->servicesMap = $servicesMap;
		$this->container = $container;
	}

	public function get(string $privilege): ?Policy
	{
		$serviceName = $this->servicesMap[$privilege] ?? null;
		if ($serviceName === null) {
			return null;
		}

		$service = $this->container->getService($serviceName);

		if (!$service instanceof Policy) {
			$this->throwNotAPolicy($service, $serviceName);
		}

		$servicePrivilege = $service::getPrivilege();
		if ($servicePrivilege !== $privilege) {
			$this->throwPolicyNameMismatch($service, $serviceName, $servicePrivilege, $privilege);
		}

		return $service;
	}

	/**
	 * @return never-return
	 */
	private function throwNotAPolicy(object $service, string $serviceName): void
	{
		$serviceClass = get_class($service);
		$expectedClass = Policy::class;
		$selfClass = self::class;
		$parts = explode('\\', self::class);
		$className = array_pop($parts);

		$message = Message::create()
			->withContext("Service $serviceName returns instance of $serviceClass.")
			->withProblem("$selfClass supports only instances of $expectedClass.")
			->withSolution("Remove service from $className or return supported object type.");

		throw InvalidArgument::create()
			->withMessage($message);
	}

	/**
	 * @return never-return
	 */
	private function throwPolicyNameMismatch(
		object $service,
		string $serviceName,
		string $servicePrivilege,
		string $privilege
	): void
	{
		$serviceClass = get_class($service);
		$selfClass = self::class;
		$message = Message::create()
			->withContext("Class $serviceClass returns privilege $servicePrivilege.")
			->withProblem("It was expected to return $privilege.")
			->withSolution(
				"Register service $serviceName to $selfClass with $servicePrivilege or change the privilege " .
				"returned by class to $privilege.",
			);

		throw InvalidArgument::create()
			->withMessage($message);
	}

}
