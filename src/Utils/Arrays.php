<?php declare(strict_types = 1);

namespace Orisai\Auth\Utils;

use function array_key_exists;
use function array_merge;
use function array_shift;
use function is_array;

/**
 * @internal
 */
final class Arrays
{

	/**
	 * @param array<mixed>            $array
	 * @param non-empty-array<string> $keys
	 * @param array<mixed>            $value
	 */
	public static function addKeyValue(array &$array, array $keys, array $value): void
	{
		$currentKey = array_shift($keys);

		if (!array_key_exists($currentKey, $array)) {
			$array[$currentKey] = [];
		}

		if ($keys !== []) {
			self::addKeyValue($array[$currentKey], $keys, $value);

			return;
		}

		$array[$currentKey] = array_merge($value, $array[$currentKey]);
	}

	/**
	 * @param array<mixed>            $array
	 * @param non-empty-array<string> $keys
	 * @return array<mixed>|null
	 */
	public static function getKey(array $array, array $keys): ?array
	{
		$currentKey = array_shift($keys);

		if (!array_key_exists($currentKey, $array)) {
			return null;
		}

		if ($keys !== []) {
			return self::getKey($array[$currentKey], $keys);
		}

		return $array[$currentKey];
	}

	/**
	 * @param array<mixed>            $array
	 * @param non-empty-array<string> $keys
	 */
	public static function removeKey(array &$array, array $keys): void
	{
		$currentKey = array_shift($keys);

		// Key was already removed
		if (!array_key_exists($currentKey, $array)) {
			return;
		}

		// Remove recursively if there are more keys left
		if ($keys !== []) {
			self::removeKey($array[$currentKey], $keys);
		}

		// Remove if current key should be removed or is empty
		if ($keys === [] || $array[$currentKey] === []) {
			unset($array[$currentKey]);
		}
	}

	/**
	 * @param array<mixed> $first
	 * @param array<mixed> $second
	 */
	public static function removeMatchingPartsFromFromFirstArray(array &$first, array $second): void
	{
		foreach ($second as $key => $value) {
			if (!array_key_exists($key, $first)) {
				continue;
			}

			if (is_array($value) && $value !== [] && is_array($first[$key]) && $first[$key] !== []) {
				self::removeMatchingPartsFromFromFirstArray($first[$key], $value);
			}

			if ($value === $first[$key] || ($first[$key] === [] && is_array($value))) {
				unset($first[$key]);
			}
		}
	}

	/**
	 * @param array<mixed> $array
	 * @return array<int, string>
	 */
	public static function keysToStrings(array $array, ?string $baseKey = null): array
	{
		$stringsByKey = [];

		foreach ($array as $key => $value) {
			$compositeKey = $baseKey !== null
				? "$baseKey.$key"
				: $key;

			$stringsByKey[] = is_array($value) && $value !== []
				? self::keysToStrings($value, $compositeKey)
				: [$compositeKey];
		}

		return array_merge(...$stringsByKey);
	}

}
