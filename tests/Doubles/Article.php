<?php declare(strict_types = 1);

namespace Tests\Orisai\Auth\Doubles;

final class Article
{

	private User $author;

	public function __construct(User $author)
	{
		$this->author = $author;
	}

	public function getAuthor(): User
	{
		return $this->author;
	}

}
