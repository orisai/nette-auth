<?php declare(strict_types = 1);

namespace Tests\OriNette\Auth\Unit\DI;

use OriNette\DI\Boot\ManualConfigurator;
use Orisai\Auth\Authentication\Firewall;
use Orisai\Auth\Authentication\IntIdentity;
use Orisai\Auth\Authentication\SimpleFirewall;
use PHPUnit\Framework\TestCase;
use Tests\OriNette\Auth\Doubles\Article;
use Tests\OriNette\Auth\Doubles\ArticleEditPolicy;
use Tests\OriNette\Auth\Doubles\User;
use function assert;
use function dirname;
use function mkdir;
use const PHP_VERSION_ID;

final class NetteDISetupTest extends TestCase
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

	public function testBuild(): void
	{
		$configurator = new ManualConfigurator($this->rootDir);
		$configurator->setForceReloadContainer();
		$configurator->addConfig(__DIR__ . '/config.full.neon');

		$container = $configurator->createContainer();

		self::assertInstanceOf(SimpleFirewall::class, $container->getService('auth.api.firewall'));
		self::assertInstanceOf(SimpleFirewall::class, $container->getService('auth.admin.firewall'));
		self::assertInstanceOf(SimpleFirewall::class, $container->getService('auth.front.firewall'));
	}

	/**
	 * @runInSeparateProcess
	 */
	public function testPolicy(): void
	{
		$configurator = new ManualConfigurator($this->rootDir);
		$configurator->setForceReloadContainer();
		$configurator->addConfig(__DIR__ . '/config.full.neon');

		$container = $configurator->createContainer();

		$firewall = $container->getService('auth.front.firewall');
		assert($firewall instanceof Firewall);

		$firewall->login(new IntIdentity(1, ['editor']));
		self::assertTrue($firewall->isAllowed(...ArticleEditPolicy::get(new Article(new User(1)))));
		self::assertTrue($firewall->isAllowed(...ArticleEditPolicy::get(new Article(new User(2)))));
	}

}
