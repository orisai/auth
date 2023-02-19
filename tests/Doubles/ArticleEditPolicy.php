<?php declare(strict_types = 1);

namespace Tests\Orisai\Auth\Doubles;

use Generator;
use Orisai\Auth\Authentication\Identity;
use Orisai\Auth\Authorization\AccessEntry;
use Orisai\Auth\Authorization\AccessEntryResult;
use Orisai\Auth\Authorization\Policy;
use Orisai\Auth\Authorization\PolicyContext;

/**
 * @phpstan-implements Policy<Article>
 */
final class ArticleEditPolicy implements Policy
{

	public const EditAll = 'article.edit.all';

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
	public function isAllowed(Identity $identity, object $requirements, PolicyContext $context): Generator
	{
		$authorizer = $context->getAuthorizer();

		$res = $authorizer->isAllowed($identity, self::EditAll)
			|| $authorizer->isAllowed($identity, ArticleEditOwnedPolicy::getPrivilege(), $requirements);

		yield new AccessEntry(
			AccessEntryResult::fromBool($res),
			'',
		);
	}

}
