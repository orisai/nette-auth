<?php declare(strict_types = 1);

namespace OriNette\Auth\Tracy;

use Orisai\Auth\Authentication\Firewall;
use Orisai\Auth\Authentication\Identity;
use Tracy\Helpers;
use Tracy\IBarPanel;

/**
 * @internal
 */
final class AuthPanel implements IBarPanel
{

	/** @var array<int|string, Firewall<Identity>> */
	private array $firewalls = [];

	public function getTab(): string
	{
		if ($this->firewalls === []) {
			return '';
		}

		return Helpers::capture(function (): void {
			// phpcs:ignore SlevomatCodingStandard.Variables.UnusedVariable.UnusedVariable
			$panel = $this;

			require __DIR__ . '/AuthPanel.tab.phtml';
		});
	}

	public function getPanel(): string
	{
		if ($this->firewalls === []) {
			return '';
		}

		return Helpers::capture(function (): void {
			// phpcs:ignore SlevomatCodingStandard.Variables.UnusedVariable.UnusedVariable
			$panel = $this;

			require __DIR__ . '/AuthPanel.panel.phtml';
		});
	}

	/**
	 * @param Firewall<Identity> $firewall
	 */
	public function addFirewall(Firewall $firewall): void
	{
		$this->firewalls[] = $firewall;
	}

	/**
	 * @return array<int|string, Firewall<Identity>>
	 */
	public function getFirewalls(): array
	{
		return $this->firewalls;
	}

}
