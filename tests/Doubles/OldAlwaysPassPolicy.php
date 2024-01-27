<?php declare(strict_types = 1);

namespace Tests\OriNette\Auth\Doubles;

use Orisai\Auth\Authentication\Identity;
use Orisai\Auth\Authorization\NoRequirements;
use Orisai\Auth\Authorization\Policy;
use Orisai\Auth\Authorization\PolicyContext;

/**
 * Compat - orisai/auth v1
 *
 * @implements Policy<NoRequirements>
 */
final class OldAlwaysPassPolicy implements Policy
{

	public static function getPrivilege(): string
	{
		return 'always-pass';
	}

	public static function getRequirementsClass(): string
	{
		return NoRequirements::class;
	}

	public function isAllowed(Identity $identity, object $requirements, PolicyContext $context): bool
	{
		return true;
	}

}
