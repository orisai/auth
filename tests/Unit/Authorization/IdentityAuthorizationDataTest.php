<?php declare(strict_types = 1);

namespace Tests\Orisai\Auth\Unit\Authorization;

use Orisai\Auth\Authorization\IdentityAuthorizationData;
use PHPUnit\Framework\TestCase;

final class IdentityAuthorizationDataTest extends TestCase
{

	public function test(): void
	{
		$data = new IdentityAuthorizationData(
			$id = 1,
			$allowedPrivileges = [
				'article' => [
					'view' => [],
					'edit' => [],
				],
			],
		);

		self::assertSame($id, $data->getId());
		self::assertSame($allowedPrivileges, $data->getRawAllowedPrivileges());
		self::assertSame(
			['article.view', 'article.edit'],
			$data->getAllowedPrivileges(),
		);
	}

}
