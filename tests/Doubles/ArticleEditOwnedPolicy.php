<?php declare(strict_types = 1);

namespace Tests\Orisai\Auth\Doubles;

use Orisai\Auth\Authentication\Identity;
use Orisai\Auth\Authorization\Authorizer;
use Orisai\Auth\Authorization\Policy;

/**
 * @phpstan-implements Policy<Article>
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
	 * @param Article $requirements
	 */
	public function isAllowed(Identity $identity, object $requirements, Authorizer $authorizer): bool
	{
		return $authorizer->hasPrivilege($identity, self::getPrivilege())
			&& $identity->getId() === $requirements->getAuthor()->getId();
	}

	/**
	 * @return array{string, object}
	 */
	public static function get(Article $article): array
	{
		return [self::getPrivilege(), $article];
	}

}
