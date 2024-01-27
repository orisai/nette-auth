<?php declare(strict_types = 1);

namespace Tests\OriNette\Auth\Unit\DI;

use OriNette\Auth\DI\LazyPolicyManager;
use OriNette\Auth\Http\SessionLoginStorage;
use OriNette\Auth\Tracy\AuthPanel;
use OriNette\DI\Boot\ManualConfigurator;
use Orisai\Auth\Authentication\ArrayLoginStorage;
use Orisai\Auth\Authentication\Firewall;
use Orisai\Auth\Authentication\IntIdentity;
use Orisai\Auth\Authentication\LoginStorage;
use Orisai\Auth\Authentication\SimpleFirewall;
use Orisai\Auth\Authorization\AccessEntry;
use Orisai\Auth\Authorization\AuthorizationDataCreator;
use Orisai\Auth\Authorization\Authorizer;
use Orisai\Auth\Authorization\PolicyManager;
use Orisai\Auth\Authorization\PrivilegeAuthorizer;
use Orisai\Auth\Passwords\Argon2PasswordHasher;
use Orisai\Auth\Passwords\PasswordHasher;
use Orisai\Exceptions\Logic\InvalidArgument;
use PHPUnit\Framework\TestCase;
use Tests\OriNette\Auth\Doubles\AlwaysPassPolicy;
use Tests\OriNette\Auth\Doubles\NeverPassPolicy;
use Tests\OriNette\Auth\Doubles\OldAlwaysPassPolicy;
use Tests\OriNette\Auth\Doubles\OldNeverPassPolicy;
use Tracy\Bar;
use function class_exists;
use function dirname;
use function mkdir;
use const PHP_VERSION_ID;

final class AuthExtensionTest extends TestCase
{

	private string $rootDir;

	protected function setUp(): void
	{
		parent::setUp();

		$this->rootDir = dirname(__DIR__, 3);
		if (PHP_VERSION_ID < 8_01_00) {
			@mkdir("$this->rootDir/var/build");
		}
	}

	public function testMinimal(): void
	{
		$configurator = new ManualConfigurator($this->rootDir);
		$configurator->setForceReloadContainer();
		$configurator->addConfig(__DIR__ . '/AuthExtension.minimal.neon');

		$container = $configurator->createContainer();

		$passwordHasher = $container->getService('orisai.auth.passwordHasher');
		self::assertInstanceOf(Argon2PasswordHasher::class, $passwordHasher);
		self::assertSame($passwordHasher, $container->getByType(PasswordHasher::class));

		$arrayStorage = $container->getService('orisai.auth.storage.array');
		self::assertInstanceOf(ArrayLoginStorage::class, $arrayStorage);
		self::assertSame($arrayStorage, $container->getByType(ArrayLoginStorage::class));

		self::assertFalse($container->hasService('orisai.auth.storage.session'));
		self::assertNull($container->getByType(SessionLoginStorage::class, false));

		self::assertSame([
			'orisai.auth.storage.array',
		], $container->findByType(LoginStorage::class));

		$authorizer = $container->getService('orisai.auth.authorizer');
		self::assertInstanceOf(PrivilegeAuthorizer::class, $authorizer);
		self::assertSame($authorizer, $container->getByType(Authorizer::class));

		$policyManager = $container->getService('orisai.auth.policyManager');
		self::assertInstanceOf(LazyPolicyManager::class, $policyManager);
		self::assertNull($container->getByType(PolicyManager::class, false));

		self::assertFalse($container->hasService('orisai.auth.panel'));
	}

	public function testSessionStorage(): void
	{
		$configurator = new ManualConfigurator($this->rootDir);
		$configurator->setForceReloadContainer();
		$configurator->addConfig(__DIR__ . '/AuthExtension.sessionStorage.neon');

		$container = $configurator->createContainer();

		$arrayStorage = $container->getService('orisai.auth.storage.array');
		self::assertInstanceOf(ArrayLoginStorage::class, $arrayStorage);
		self::assertSame($arrayStorage, $container->getByType(ArrayLoginStorage::class));

		$sessionStorage = $container->getService('orisai.auth.storage.session');
		self::assertInstanceOf(SessionLoginStorage::class, $sessionStorage);
		self::assertSame($sessionStorage, $container->getByType(SessionLoginStorage::class));

		self::assertSame([
			'orisai.auth.storage.array',
			'orisai.auth.storage.session',
		], $container->findByType(LoginStorage::class));
	}

	public function testPolicy(): void
	{
		$configurator = new ManualConfigurator($this->rootDir);
		$configurator->setForceReloadContainer();
		// Compat - orisai/auth v1
		if (class_exists(AccessEntry::class)) {
			$configurator->addConfig(__DIR__ . '/AuthExtension.policy.neon');
		} else {
			$configurator->addConfig(__DIR__ . '/AuthExtension.policy.old.neon');
		}

		$container = $configurator->createContainer();

		$authorizer = $container->getService('orisai.auth.authorizer');
		self::assertInstanceOf(PrivilegeAuthorizer::class, $authorizer);
		self::assertSame($authorizer, $container->getByType(Authorizer::class));

		$policyManager = $container->getService('orisai.auth.policyManager');
		self::assertInstanceOf(LazyPolicyManager::class, $policyManager);
		self::assertNull($container->getByType(PolicyManager::class, false));

		$identity = new IntIdentity(1, []);

		$missingPolicy = $policyManager->get('missing');
		self::assertNull($missingPolicy);

		// Compat - orisai/auth v1
		$neverPassPolicyClass = class_exists(AccessEntry::class) ? NeverPassPolicy::class : OldNeverPassPolicy::class;
		$neverPassPolicy = $policyManager->get($neverPassPolicyClass::getPrivilege());
		self::assertInstanceOf($neverPassPolicyClass, $neverPassPolicy);
		self::assertFalse($authorizer->isAllowed($identity, $neverPassPolicyClass::getPrivilege()));

		// Compat - orisai/auth v1
		$alwaysPassPolicyClass = class_exists(
			AccessEntry::class,
		) ? AlwaysPassPolicy::class : OldAlwaysPassPolicy::class;
		$alwaysPassPolicy = $policyManager->get($alwaysPassPolicyClass::getPrivilege());
		self::assertInstanceOf($alwaysPassPolicyClass, $alwaysPassPolicy);
		self::assertTrue($authorizer->isAllowed($identity, $alwaysPassPolicyClass::getPrivilege()));
	}

	public function testPolicyIsWrong(): void
	{
		$configurator = new ManualConfigurator($this->rootDir);
		$configurator->setForceReloadContainer();
		$configurator->addConfig(__DIR__ . '/AuthExtension.policy.abstract.neon');

		$this->expectException(InvalidArgument::class);
		$this->expectExceptionMessage(
			<<<'MSG'
Context: Adding 'abstractPolicy' service to policy manager.
Problem: Service type is an abstract class and cannot be resolved.
Solution: Add only non-abstract policies to services.
MSG,
		);

		$configurator->createContainer();
	}

	/**
	 * @runInSeparateProcess
	 */
	public function testDebugPanel(): void
	{
		$configurator = new ManualConfigurator($this->rootDir);
		$configurator->setForceReloadContainer();
		$configurator->addConfig(__DIR__ . '/AuthExtension.debugPanel.neon');

		$container = $configurator->createContainer();

		$panel = $container->getService('orisai.auth.panel');
		self::assertInstanceOf(AuthPanel::class, $panel);
		self::assertNull($container->getByType(AuthPanel::class, false));

		$bar = $container->getByType(Bar::class);
		self::assertSame($panel, $bar->getPanel('orisai.auth.panel'));

		self::assertSame([], $panel->getFirewalls());
	}

	/**
	 * @runInSeparateProcess
	 */
	public function testAddFirewallToPanel(): void
	{
		$configurator = new ManualConfigurator($this->rootDir);
		$configurator->setForceReloadContainer();
		$configurator->addConfig(__DIR__ . '/AuthExtension.addFirewallToPanel.neon');

		$container = $configurator->createContainer();

		$firewall = $container->getByType(Firewall::class);
		self::assertInstanceOf(SimpleFirewall::class, $firewall);
		self::assertSame($firewall->getAuthorizer(), $container->getByType(Authorizer::class));

		$panel = $container->getService('orisai.auth.panel');
		self::assertInstanceOf(AuthPanel::class, $panel);

		self::assertSame(
			[
				$firewall,
			],
			$panel->getFirewalls(),
		);
	}

	public function testAuthDataCreator(): void
	{
		$configurator = new ManualConfigurator($this->rootDir);
		$configurator->setForceReloadContainer();
		$configurator->addConfig(__DIR__ . '/AuthExtension.authDataCreator.neon');

		$container = $configurator->createContainer();

		$authorizer = $container->getByType(Authorizer::class);
		$authData = $authorizer->getData();

		self::assertSame(['role'], $authData->getRoles());
		self::assertSame(['privilege'], $authData->getPrivileges());

		$authDataCreator = $container->getByType(AuthorizationDataCreator::class);
		self::assertEquals($authData, $authDataCreator->create());
	}

}
