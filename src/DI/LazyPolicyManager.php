<?php declare(strict_types = 1);

namespace OriNette\Auth\DI;

use OriNette\DI\Services\ServiceManager;
use Orisai\Auth\Authorization\Policy;
use Orisai\Auth\Authorization\PolicyManager;
use Orisai\Exceptions\Logic\InvalidArgument;
use Orisai\Exceptions\Message;
use function get_class;

/**
 * @internal
 */
final class LazyPolicyManager extends ServiceManager implements PolicyManager
{

	public function get(string $privilege): ?Policy
	{
		$service = $this->getTypedService($privilege, Policy::class);

		if ($service === null) {
			return null;
		}

		$servicePrivilege = $service::getPrivilege();
		if ($servicePrivilege !== $privilege) {
			$this->throwPolicyNameMismatch($service, $servicePrivilege, $privilege);
		}

		return $service;
	}

	/**
	 * @return never
	 */
	private function throwPolicyNameMismatch(
		object $service,
		string $servicePrivilege,
		string $privilege
	): void
	{
		$serviceClass = get_class($service);
		$serviceName = $this->getServiceName($privilege);
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
