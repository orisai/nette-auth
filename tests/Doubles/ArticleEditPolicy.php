<?php declare(strict_types = 1);

namespace Tests\OriNette\Auth\Doubles;

use Orisai\Auth\Authentication\Identity;
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
	public function isAllowed(Identity $identity, object $requirements, PolicyContext $context): bool
	{
		$authorizer = $context->getAuthorizer();

		return $authorizer->isAllowed($identity, self::EditAll)
			|| $authorizer->isAllowed($identity, ...ArticleEditOwnedPolicy::get($requirements));
	}

	/**
	 * @return array{string, object}
	 */
	public static function get(Article $article): array
	{
		return [self::getPrivilege(), $article];
	}

}
