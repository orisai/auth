<?php declare(strict_types = 1);

namespace Tests\Orisai\Auth\Doubles;

use Orisai\Auth\Authentication\Firewall;
use Orisai\Auth\Authorization\Policy;

/**
 * @phpstan-implements Policy<UserAwareFirewall>
 */
final class ArticleEditPolicy implements Policy
{

	public const EDIT_ALL = 'article.edit.all';

	private Article $article;

	public function __construct(Article $article)
	{
		$this->article = $article;
	}

	public static function getPrivilege(): string
	{
		return 'article.edit';
	}

	public function isAllowed(Firewall $firewall): bool
	{
		return $firewall->isAllowed(self::EDIT_ALL)
			|| $firewall->isAllowed(new ArticleEditOwnedPolicy($this->article));
	}

}
