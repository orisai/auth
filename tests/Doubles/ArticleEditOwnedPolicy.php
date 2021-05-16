<?php declare(strict_types = 1);

namespace Tests\Orisai\Auth\Doubles;

use Orisai\Auth\Authentication\Firewall;
use Orisai\Auth\Authorization\Policy;

/**
 * @phpstan-implements Policy<UserAwareFirewall, Article>
 */
final class ArticleEditOwnedPolicy implements Policy
{

	public static function getPrivilege(): string
	{
		return 'article.edit.owned';
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
		return $firewall->hasPrivilege(self::getPrivilege())
			&& $firewall->getUser()->getId() === $requirements->getAuthor()->getId();
	}

	/**
	 * @return array{string, object}
	 */
	public static function get(Article $article): array
	{
		return [self::getPrivilege(), $article];
	}

}
