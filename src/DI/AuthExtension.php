<?php declare(strict_types = 1);

namespace OriNette\Auth\DI;

use Nette\DI\CompilerExtension;
use Nette\DI\ContainerBuilder;
use Nette\DI\Definitions\Reference;
use Nette\DI\Definitions\ServiceDefinition;
use Nette\Http\Session;
use Nette\PhpGenerator\Literal;
use Nette\Schema\Expect;
use Nette\Schema\Schema;
use OriNette\Auth\Http\SessionLoginStorage;
use OriNette\Auth\Tracy\AuthPanel;
use OriNette\DI\Definitions\DefinitionsLoader;
use Orisai\Auth\Authentication\ArrayLoginStorage;
use Orisai\Auth\Authentication\Firewall;
use Orisai\Auth\Authorization\AuthorizationData;
use Orisai\Auth\Authorization\AuthorizationDataBuilder;
use Orisai\Auth\Authorization\Authorizer;
use Orisai\Auth\Authorization\Policy;
use Orisai\Auth\Authorization\PolicyManager;
use Orisai\Auth\Authorization\PrivilegeAuthorizer;
use Orisai\Auth\Passwords\PasswordEncoder;
use Orisai\Auth\Passwords\SodiumPasswordEncoder;
use Orisai\Exceptions\Logic\InvalidArgument;
use Orisai\Exceptions\Message;
use ReflectionClass;
use stdClass;
use Tracy\Bar;
use function assert;
use function is_a;
use function is_array;
use function serialize;

/**
 * @property-read stdClass $config
 */
final class AuthExtension extends CompilerExtension
{

	private ServiceDefinition $policyManagerDefinition;

	private ?ServiceDefinition $panelDefinition = null;

	public function getConfigSchema(): Schema
	{
		return Expect::structure([
			'authorization' => Expect::structure([
				'data' => DefinitionsLoader::schema()->nullable(),
			]),
			'debug' => Expect::structure([
				'panel' => Expect::bool(false),
			]),
		]);
	}

	public function loadConfiguration(): void
	{
		parent::loadConfiguration();
		$builder = $this->getContainerBuilder();
		$config = $this->config;
		$loader = new DefinitionsLoader($this->compiler);

		$this->registerPasswordEncoder($builder);
		$this->registerDebugPanel($config, $builder);
		$policyManagerDefinition = $this->registerPolicyManager($builder);
		$this->registerAuthorizer($config, $builder, $loader, $policyManagerDefinition);
		$this->registerStorages($builder);
	}

	public function beforeCompile(): void
	{
		parent::beforeCompile();
		$builder = $this->getContainerBuilder();

		$this->addPoliciesToPolicyManager($builder);
		$this->addDebugPanelToTracy($builder);
		$this->addFirewallsToDebugPanel($builder, $this->panelDefinition);
		$this->unregisterStoragesWithMissingRequirements($builder);
	}

	private function registerDebugPanel(stdClass $config, ContainerBuilder $builder): void
	{
		if (!$config->debug->panel) {
			return;
		}

		$this->panelDefinition = $builder->addDefinition($this->prefix('panel'))
			->setFactory(AuthPanel::class)
			->setAutowired(false);
	}

	private function addDebugPanelToTracy(ContainerBuilder $builder): void
	{
		if ($this->panelDefinition === null) {
			return;
		}

		$this->panelDefinition->addSetup('?->addPanel(?, ?)', [
			$builder->getDefinitionByType(Bar::class),
			$this->panelDefinition,
			$this->prefix('panel'),
		]);
	}

	private function addFirewallsToDebugPanel(ContainerBuilder $builder, ?ServiceDefinition $panelDefinition): void
	{
		if ($panelDefinition === null) {
			return;
		}

		foreach ($builder->findByType(Firewall::class) as $definition) {
			assert($definition instanceof ServiceDefinition);
			$definition->addSetup('?->addFirewall(?)', [
				$panelDefinition,
				$definition,
			]);
		}
	}

	private function registerPasswordEncoder(ContainerBuilder $builder): void
	{
		$builder->addDefinition($this->prefix('passwordEncoder'))
			->setFactory(SodiumPasswordEncoder::class)
			->setType(PasswordEncoder::class);
	}

	private function registerStorages(ContainerBuilder $builder): void
	{
		$builder->addDefinition($this->prefix('storage.array'))
			->setFactory(ArrayLoginStorage::class);

		$builder->addDefinition($this->prefix('storage.session'))
			->setFactory(SessionLoginStorage::class);
	}

	private function unregisterStoragesWithMissingRequirements(ContainerBuilder $builder): void
	{
		if ($builder->getByType(Session::class) === null) {
			$builder->removeDefinition($this->prefix('storage.session'));
		}
	}

	private function registerPolicyManager(ContainerBuilder $builder): ServiceDefinition
	{
		return $this->policyManagerDefinition = $builder->addDefinition($this->prefix('policyManager'))
			->setFactory(LazyPolicyManager::class)
			->setType(PolicyManager::class)
			->setAutowired(false);
	}

	private function addPoliciesToPolicyManager(ContainerBuilder $builder): void
	{
		$privilegeServiceNameMap = [];
		foreach ($builder->findByType(Policy::class) as $definition) {
			$definitionName = $definition->getName();
			assert($definitionName !== null);

			$type = $definition->getType();
			assert($type !== null && is_a($type, Policy::class, true));

			if ((new ReflectionClass($type))->isAbstract()) {
				$message = Message::create()
					->withContext("Adding '$definitionName' service to policy manager.")
					->withProblem('Service type is an abstract class and cannot be resolved.')
					->withSolution('Add only non-abstract policies to services.');

				throw InvalidArgument::create()
					->withMessage($message);
			}

			$policyPrivilege = $type::getPrivilege();
			$privilegeServiceNameMap[$policyPrivilege] = $definitionName;
		}

		$this->policyManagerDefinition->setArgument('serviceMap', $privilegeServiceNameMap);
	}

	private function registerAuthorizer(
		stdClass $config,
		ContainerBuilder $builder,
		DefinitionsLoader $loader,
		ServiceDefinition $policyManagerDefinition
	): void
	{
		$dataConfig = $config->authorization->data;
		if ($dataConfig === null) {
			$authData = (new AuthorizationDataBuilder())->build();
			$authorizationDataDefinition = $builder->addDefinition($this->prefix('authorizationData'))
				->setFactory('\unserialize(\'?\', [?])', [
					new Literal(serialize($authData)),
					AuthorizationData::class,
				])
				->setType(AuthorizationData::class);
		} else {
			$authorizationDataDefinition = $loader->loadDefinitionFromConfig(
				$dataConfig,
				$this->prefix('authorizationData'),
			);
		}

		if (
			(!is_array($dataConfig) || !isset($dataConfig['autowired']))
			&& !$authorizationDataDefinition instanceof Reference
		) {
			$authorizationDataDefinition->setAutowired();
		}

		$builder->addDefinition($this->prefix('authorizer'))
			->setFactory(PrivilegeAuthorizer::class, [
				$policyManagerDefinition,
				$authorizationDataDefinition,
			])
			->setType(Authorizer::class);
	}

}
