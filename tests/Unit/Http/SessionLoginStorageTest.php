<?php declare(strict_types = 1);

namespace Tests\OriNette\Auth\Unit\Http;

use Nette\Http\Request;
use Nette\Http\Response;
use Nette\Http\Session;
use Nette\Http\UrlScript;
use OriNette\Auth\Http\SessionLoginStorage;
use Orisai\Auth\Authentication\LoginStorage;
use PHPUnit\Framework\TestCase;

/**
 * @runTestsInSeparateProcesses
 */
final class SessionLoginStorageTest extends TestCase
{

	private function createSession(): Session
	{
		return new Session(new Request(new UrlScript('https://orisai.dev')), new Response());
	}

	private function createStorage(Session $session): LoginStorage
	{
		return new SessionLoginStorage($session);
	}

	public function testBase(): void
	{
		$session = $this->createSession();
		$storage = $this->createStorage($session);
		$sectionName = 'Orisai.Auth.Logins/public';

		self::assertFalse($storage->alreadyExists('public'));
		self::assertFalse($session->hasSection($sectionName));

		$logins = $storage->getLogins('public');

		self::assertTrue($storage->alreadyExists('public'));
		self::assertTrue($session->hasSection($sectionName));

		self::assertNull($logins->getCurrentLogin());
		self::assertSame([], $logins->getExpiredLogins());

		$section = $session->getSection($sectionName);
		self::assertSame(2, $section->get('version'));
		self::assertSame($logins, $section->get('logins'));
	}

	public function testRegenerateId(): void
	{
		$session = $this->createSession();
		$storage = $this->createStorage($session);

		$sessionId = $session->getId();
		$storage->regenerateSecurityToken('doesnt matter');
		self::assertNotSame($sessionId, $session->getId());
	}

	public function testNotConflicting(): void
	{
		$session = $this->createSession();
		$storage = $this->createStorage($session);

		$loginsPublic = $storage->getLogins('public');
		$loginsAdmin = $storage->getLogins('admin');

		self::assertNotSame($loginsAdmin, $loginsPublic);
	}

	public function testUseExistingSession(): void
	{
		$session = $this->createSession();

		$storage = $this->createStorage($session);
		$logins = $storage->getLogins('test');
		self::assertSame($logins, $storage->getLogins('test'));

		$storage = $this->createStorage($session);
		self::assertSame($logins, $storage->getLogins('test'));
	}

}
