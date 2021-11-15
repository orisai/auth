<?php declare(strict_types = 1);

namespace Orisai\Auth\Authorization;

use Orisai\Auth\Utils\Arrays;

final class IdentityAuthorizationData
{

	/** @var int|string */
	private $id;

	/** @var array<mixed> */
	private array $rawAllowedPrivileges;

	/**
	 * Accepts preprocessed data from builder
	 *
	 * @param int|string   $id
	 * @param array<mixed> $rawAllowedPrivileges
	 *
	 * @internal
	 */
	public function __construct($id, array $rawAllowedPrivileges)
	{
		$this->id = $id;
		$this->rawAllowedPrivileges = $rawAllowedPrivileges;
	}

	/**
	 * @return int|string
	 */
	public function getId()
	{
		return $this->id;
	}

	/**
	 * @return array<mixed>
	 */
	public function getRawAllowedPrivileges(): array
	{
		return $this->rawAllowedPrivileges;
	}

	/**
	 * @return array<string>
	 */
	public function getAllowedPrivileges(): array
	{
		return Arrays::keysToStrings($this->rawAllowedPrivileges);
	}

}