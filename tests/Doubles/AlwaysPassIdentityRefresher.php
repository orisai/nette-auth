<?php declare(strict_types = 1);

namespace Tests\OriNette\Auth\Doubles;

use Orisai\Auth\Authentication\Identity;
use Orisai\Auth\Authentication\IdentityRefresher;

/**
 * @phpstan-implements IdentityRefresher<Identity>
 */
final class AlwaysPassIdentityRefresher implements IdentityRefresher
{

	public function refresh(Identity $identity): Identity
	{
		return $identity;
	}

}
