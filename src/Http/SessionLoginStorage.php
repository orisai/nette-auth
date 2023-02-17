<?php declare(strict_types = 1);

namespace OriNette\Auth\Http;

use Nette\Http\Session;
use Nette\Http\SessionSection;
use Orisai\Auth\Authentication\Data\Logins;
use Orisai\Auth\Authentication\LoginStorage;
use function assert;

final class SessionLoginStorage implements LoginStorage
{

	private Session $session;

	/** @var array<int|string, Logins> */
	private array $logins = [];

	public function __construct(Session $session)
	{
		$this->session = $session;
	}

	public function regenerateSecurityToken(string $namespace): void
	{
		$this->session->regenerateId();
	}

	public function alreadyExists(string $namespace): bool
	{
		if (!$this->session->exists()) {
			return false;
		}

		return $this->session->hasSection($this->formatSectionName($namespace));
	}

	private function formatSectionName(string $namespace): string
	{
		return "Orisai.Auth.Logins/$namespace";
	}

	private function getSessionSection(string $namespace): SessionSection
	{
		$sectionName = $this->formatSectionName($namespace);

		$isNew = !$this->session->hasSection($sectionName);

		$section = $this->session->getSection($sectionName);

		if ($isNew) {
			$this->setDefaults($section);
		}

		return $section;
	}

	public function getLogins(string $namespace): Logins
	{
		if (isset($this->logins[$namespace])) {
			return $this->logins[$namespace];
		}

		$logins = $this->getSessionSection($namespace)->get('logins');
		assert($logins instanceof Logins);

		return $this->logins[$namespace] = $logins;
	}

	private function setDefaults(SessionSection $section): void
	{
		$section->set('version', 2);
		$section->set('logins', new Logins());
	}

	public function __destruct()
	{
		foreach ($this->logins as $namespace => $login) {
			if ($login->getCurrentLogin() === null && $login->getExpiredLogins() === []) {
				$this->session->getSection($this->formatSectionName((string) $namespace))->remove();
			}
		}
	}

}
