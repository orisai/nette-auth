<?php declare(strict_types = 1);

namespace Tests\OriNette\Auth\Unit\DI;

use OriNette\Auth\DI\LazyPolicyManager;
use OriNette\DI\Boot\ManualConfigurator;
use Orisai\Exceptions\Logic\InvalidArgument;
use PHPUnit\Framework\TestCase;
use Tests\OriNette\Auth\Doubles\AlwaysPassPolicy;
use function dirname;
use function mkdir;
use const PHP_VERSION_ID;

final class LazyPolicyManagerTest extends TestCase
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

	public function test(): void
	{
		$configurator = new ManualConfigurator($this->rootDir);
		$configurator->setForceReloadContainer();
		$configurator->addConfig(__DIR__ . '/LazyPolicyManager.neon');

		$container = $configurator->createContainer();

		$manager = $container->getByType(LazyPolicyManager::class);

		self::assertInstanceOf(AlwaysPassPolicy::class, $manager->get(AlwaysPassPolicy::getPrivilege()));

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
Context: Class Tests\OriNette\Auth\Doubles\AlwaysPassPolicy returns privilege
         always-pass.
Problem: It was expected to return not.matching.privilege.
Solution: Register service policy.alwaysPass to
          OriNette\Auth\DI\LazyPolicyManager with always-pass or change the
          privilege returned by class to not.matching.privilege.
MSG,
		);
	}

}
