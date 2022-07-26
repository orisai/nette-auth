<?php declare(strict_types = 1);

namespace Tests\OriNette\Auth\Unit\Tracy;

use OriNette\Auth\Tracy\AuthPanel;
use Orisai\Auth\Authentication\ArrayLoginStorage;
use Orisai\Auth\Authentication\SimpleFirewall;
use Orisai\Auth\Authorization\AuthorizationDataBuilder;
use Orisai\Auth\Authorization\PrivilegeAuthorizer;
use Orisai\Auth\Authorization\SimpleAuthorizationDataCreator;
use Orisai\Auth\Authorization\SimplePolicyManager;
use PHPUnit\Framework\TestCase;
use Tests\OriNette\Auth\Doubles\AlwaysPassIdentityRefresher;

final class AuthPanelTest extends TestCase
{

	public function test(): void
	{
		$panel = new AuthPanel();

		self::assertSame([], $panel->getFirewalls());
		self::assertSame('', $panel->getTab());
		self::assertSame('', $panel->getPanel());

		$firewall = new SimpleFirewall(
			'a',
			new ArrayLoginStorage(),
			new AlwaysPassIdentityRefresher(),
			new PrivilegeAuthorizer(
				new SimplePolicyManager(),
				new SimpleAuthorizationDataCreator(new AuthorizationDataBuilder()),
			),
		);
		$panel->addFirewall($firewall);

		self::assertSame([$firewall], $panel->getFirewalls());
		self::assertNotEmpty($panel->getTab());
		self::assertNotEmpty($panel->getPanel());
	}

}
