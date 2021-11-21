<?php declare(strict_types = 1);

namespace Orisai\Auth\Bridge\NetteHttp;

use Nette\Http\Session;
use Nette\Http\SessionSection;
use Orisai\Auth\Authentication\Data\Logins;
use Orisai\Auth\Authentication\LoginStorage;
use function assert;

final class SessionLoginStorage implements LoginStorage
{

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
		return "Orisai.Auth.Logins/$namespace";
	}

	private function getSessionSection(string $namespace): SessionSection
	{
		$sectionName = $this->formatSectionName($namespace);

		$isNew = !$this->session->hasSection($sectionName);

		$section = $this->session->getSection($sectionName);
		$section->warnOnUndefined = true;

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

		$logins = $this->getSessionSection($namespace)->logins;
		assert($logins instanceof Logins);

		return $this->logins[$namespace] = $logins;
	}

	private function setDefaults(SessionSection $section): void
	{
		$section->version = 2;
		$section->logins = new Logins();
	}

}
