<?php declare(strict_types = 1);

namespace Tests\Orisai\Auth\Doubles;

use Orisai\Auth\Authentication\Firewall;
use Orisai\Auth\Authorization\Policy;

/**
 * @phpstan-implements Policy<UserAwareFirewall>
 */
final class ArticleEditOwnedPolicy implements Policy
{

	private Article $article;

	public function __construct(Article $article)
	{
		$this->article = $article;
	}

	public static function getPrivilege(): string
	{
		return 'article.edit.owned';
	}

	public function isAllowed(Firewall $firewall): bool
	{
		return $firewall->hasPrivilege(self::getPrivilege())
			&& $firewall->getUser()->getId() === $this->article->getAuthor()->getId();
	}

}
