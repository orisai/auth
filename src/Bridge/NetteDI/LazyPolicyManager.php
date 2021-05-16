<?php declare(strict_types = 1);

namespace Orisai\Auth\Bridge\NetteDI;

use Nette\DI\Container;
use Orisai\Auth\Authorization\Policy;
use Orisai\Auth\Authorization\PolicyManager;
use Orisai\Exceptions\Logic\InvalidArgument;
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
			$serviceClass = get_class($service);
			$expectedClass = Policy::class;

			throw InvalidArgument::create()
				->withMessage(
					"Service $serviceName returns class $serviceClass which is not a subclass of $expectedClass.",
				);
		}

		$servicePrivilege = $service::getPrivilege();
		if ($servicePrivilege !== $privilege) {
			$serviceClass = get_class($service);

			throw InvalidArgument::create()
				->withMessage(
					"Service $serviceName returns class $serviceClass which is bounded to privilege $servicePrivilege instead of $privilege.",
				);
		}

		return $service;
	}

}
