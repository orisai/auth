<?php declare(strict_types = 1);

namespace Orisai\Auth\Bridge\NetteHttp;

use Nette\Http\Session;
use Nette\Http\SessionSection;
use Orisai\Auth\Authentication\Data\CurrentExpiration;
use Orisai\Auth\Authentication\Data\CurrentLogin;
use Orisai\Auth\Authentication\Data\ExpiredLogin;
use Orisai\Auth\Authentication\Data\Logins;
use Orisai\Auth\Authentication\LoginStorage;
use function assert;
use function time;

final class NetteSessionLoginStorage implements LoginStorage
{

	private const SESSION_PREFIX = 'orisai.auth';

	private Session $session;

	/** @var array<Logins> */
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
		return self::SESSION_PREFIX . '.' . $namespace;
	}

	private function getSessionSection(string $namespace): SessionSection
	{
		$sectionName = $this->formatSectionName($namespace);

		$isNew = !$this->session->hasSection($sectionName);

		$section = $this->session->getSection($sectionName);
		$section->warnOnUndefined = true;

		if ($isNew) {
			$this->setDefaults($section);
		} else {
			$this->migrateData($section);
		}

		return $section;
	}

	public function getLogins(string $namespace): Logins
	{
		if (isset($this->logins[$namespace])) {
			return $this->logins[$namespace];
		}

		$logins = $this->getSessionSection($namespace)->logins;
		assert($logins instanceof Logins);

		return $this->logins[$namespace] = $logins;
	}

	private function setDefaults(SessionSection $section): void
	{
		$section->version = 2;
		$section->logins = new Logins();
	}

	private function migrateData(SessionSection $section): void
	{
		if ($section->version !== 1) {
			return;
		}

		$section->version = 2;
		$section->logins = $logins = new Logins();

		if ($section->identity !== null) {
			$login = new CurrentLogin($section->identity, $section->authenticationTime ?? time());

			if ($section->expirationTime !== null && $section->expirationDelta !== null) {
				$expiration = new CurrentExpiration($section->expirationTime, $section->expirationDelta);
				$login->setExpiration($expiration);
			}

			if ($section->authenticated === true) {
				$logins->setCurrentLogin($login);
			} else {
				$logins->addExpiredLogin(new ExpiredLogin(
					$login,
					$section->logoutReason,
				));
			}
		}

		unset(
			$section->authenticated,
			$section->authenticationTime,
			$section->identity,
			$section->logoutReason,
			$section->expirationTime,
			$section->expirationDelta,
		);
	}

}
