<?php declare(strict_types = 1);

namespace Tests\OriNette\Auth\Unit\Http;

use DateTimeImmutable;
use Nette\Http\Request;
use Nette\Http\Response;
use Nette\Http\Session;
use Nette\Http\UrlScript;
use OriNette\Auth\Http\SessionLoginStorage;
use Orisai\Auth\Authentication\Data\CurrentLogin;
use Orisai\Auth\Authentication\Data\ExpiredLogin;
use Orisai\Auth\Authentication\IntIdentity;
use Orisai\Auth\Authentication\LoginStorage;
use Orisai\Auth\Authentication\LogoutCode;
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
		self::assertSame($logins, $storage->getLogins('public'));

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

	public function testGetExistingLoginFromSession(): void
	{
		$session = $this->createSession();
		$storage = $this->createStorage($session);

		$logins = $storage->getLogins('test');
		$login = new CurrentLogin(new IntIdentity(1, []), new DateTimeImmutable());
		$logins->setCurrentLogin($login);

		$storage = $this->createStorage($session);
		self::assertEquals($logins, $storage->getLogins('test'));
	}

	public function testRemoveEmptySection(): void
	{
		$session = $this->createSession();
		$storage = $this->createStorage($session);

		$currentLogin = new CurrentLogin(new IntIdentity(1, []), new DateTimeImmutable());
		$expiredLogin = new ExpiredLogin($currentLogin, LogoutCode::manual());

		$emptyName = 'Orisai.Auth.Logins/empty';
		self::assertFalse($session->hasSection($emptyName));
		$storage->getLogins('empty');
		self::assertTrue($session->hasSection($emptyName));

		$currentName = 'Orisai.Auth.Logins/current';
		self::assertFalse($session->hasSection($currentName));
		$current = $storage->getLogins('current');
		self::assertTrue($session->hasSection($currentName));
		$current->setCurrentLogin($currentLogin);

		$expiredName = 'Orisai.Auth.Logins/expired';
		self::assertFalse($session->hasSection($expiredName));
		$expired = $storage->getLogins('expired');
		self::assertTrue($session->hasSection($currentName));
		$expired->addExpiredLogin($expiredLogin);

		unset($storage);
		self::assertFalse($session->hasSection($emptyName));
		self::assertTrue($session->hasSection($currentName));
		self::assertTrue($session->hasSection($expiredName));
	}

	public function testNumericNamespace(): void
	{
		$session = $this->createSession();
		$storage = $this->createStorage($session);

		$namespace = '123';

		self::assertFalse($storage->alreadyExists($namespace));
		$logins = $storage->getLogins($namespace);
		self::assertSame($logins, $storage->getLogins($namespace));
		self::assertTrue($storage->alreadyExists($namespace));

		$sessionId = $session->getId();
		$storage->regenerateSecurityToken($namespace);
		self::assertNotSame($sessionId, $session->getId());

		unset($storage);
		self::assertFalse($session->hasSection("Orisai.Auth.Logins/$namespace"));
	}

}
