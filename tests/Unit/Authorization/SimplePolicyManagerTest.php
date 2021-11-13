<?php declare(strict_types = 1);

namespace Tests\Orisai\Auth\Unit\Authorization;

use Orisai\Auth\Authorization\SimplePolicyManager;
use PHPUnit\Framework\TestCase;
use Tests\Orisai\Auth\Doubles\ArticleEditPolicy;

final class SimplePolicyManagerTest extends TestCase
{

	public function test(): void
	{
		$policyManager = new SimplePolicyManager();
		self::assertNull($policyManager->get(ArticleEditPolicy::getPrivilege()));

		$policy = new ArticleEditPolicy();
		$policyManager->add($policy);
		self::assertSame($policy, $policyManager->get(ArticleEditPolicy::getPrivilege()));
	}

}
