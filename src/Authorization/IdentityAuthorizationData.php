<?php declare(strict_types = 1);

namespace Orisai\Auth\Authorization;

use Orisai\Auth\Utils\Arrays;

final class IdentityAuthorizationData
{

	/** @var int|string */
	private $id;

	/** @var array<mixed> */
	private array $rawAllowedPrivileges;

	private bool $root;

	/**
	 * Accepts preprocessed data from builder
	 *
	 * @param int|string   $id
	 * @param array<mixed> $rawAllowedPrivileges
	 *
	 * @internal
	 * @see IdentityAuthorizationDataBuilder::build()
	 */
	public function __construct($id, array $rawAllowedPrivileges, bool $root)
	{
		$this->id = $id;
		$this->rawAllowedPrivileges = $rawAllowedPrivileges;
		$this->root = $root;
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

	public function isRoot(): bool
	{
		return $this->root;
	}

	/**
	 * @return array<mixed>
	 */
	public function __serialize(): array
	{
		return [
			'id' => $this->id,
			'rawAllowedPrivileges' => $this->rawAllowedPrivileges,
			'root' => $this->root,
		];
	}

	/**
	 * @param array<mixed> $data
	 */
	public function __unserialize(array $data): void
	{
		$this->id = $data['id'];
		$this->rawAllowedPrivileges = $data['rawAllowedPrivileges'];
		$this->root = $data['root'] ?? false;
	}

}
