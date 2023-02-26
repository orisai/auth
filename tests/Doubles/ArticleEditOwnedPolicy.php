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
	public function isAllowed(Identity $identity, object $requirements, PolicyContext $context): Generator
	{
		$authorizer = $context->getAuthorizer();
		$privilege = self::getPrivilege();

		yield new AccessEntry(
			AccessEntryResult::fromBool($authorizer->hasPrivilege($identity, $privilege)),
			"Has privilege $privilege",
		);

		yield new AccessEntry(
			AccessEntryResult::fromBool($identity->getId() === $requirements->getAuthor()->getId()),
			'Is author of the article',
		);
	}

}
