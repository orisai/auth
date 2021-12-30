<?php declare(strict_types = 1);

namespace Tests\Orisai\Auth\Doubles;

use Orisai\Auth\Authentication\Identity;
use Orisai\Auth\Authorization\Policy;
use Orisai\Auth\Authorization\PolicyContext;

/**
 * @phpstan-implements Policy<Article>
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
	 * @param Article $requirements
	 */
	public function isAllowed(Identity $identity, object $requirements, PolicyContext $context): bool
	{
		$authorizer = $context->getAuthorizer();

		return $authorizer->isAllowed($identity, self::EDIT_ALL)
			|| $authorizer->isAllowed($identity, ArticleEditOwnedPolicy::getPrivilege(), $requirements);
	}

}
