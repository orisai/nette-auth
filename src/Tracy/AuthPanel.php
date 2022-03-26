<?php declare(strict_types = 1);

namespace OriNette\Auth\Tracy;

use Orisai\Auth\Authentication\Firewall;
use Orisai\Auth\Authentication\Identity;
use Tracy\Helpers;
use Tracy\IBarPanel;

final class AuthPanel implements IBarPanel
{

	/** @var array<int|string, Firewall<Identity>> */
	private array $firewalls;

	/**
	 * @param Firewall<Identity> $firewall
	 */
	public function addFirewall(Firewall $firewall): void
	{
		$this->firewalls[] = $firewall;
	}

	public function getTab(): string
	{
		return Helpers::capture(static function (): void {
			require __DIR__ . '/AuthPanel.tab.phtml';
		});
	}

	public function getPanel(): string
	{
		return Helpers::capture(function (): void {
			// phpcs:ignore SlevomatCodingStandard.Variables.UnusedVariable.UnusedVariable
			$firewalls = $this->firewalls;

			require __DIR__ . '/AuthPanel.panel.phtml';
		});
	}

}
