<?php declare(strict_types = 1);

namespace Tests\Orisai\Auth\Doubles;

use Orisai\Auth\Authentication\Firewall;
use Orisai\Auth\Authorization\Policy;

/**
 * @phpstan-implements Policy<UserAwareFirewall, Article>
 */
final class ArticleEditPolicy implements Policy
{

	public const EDIT_ALL = 'article.edit.all';

	public static function getPrivilege(): string
	{
		return 'article.edit';
	}

	public static function getRequirementsClass(): string
	{
		return Article::class;
	}

	/**
	 * @param UserAwareFirewall $firewall
	 * @param Article           $requirements
	 */
	public function isAllowed(Firewall $firewall, object $requirements): bool
	{
		return $firewall->isAllowed(self::EDIT_ALL)
			|| $firewall->isAllowed(...ArticleEditOwnedPolicy::get($requirements));
	}

	/**
	 * @return array{string, object}
	 */
	public static function get(Article $article): array
	{
		return [self::getPrivilege(), $article];
	}

}
