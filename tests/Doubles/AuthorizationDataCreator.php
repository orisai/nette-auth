<?php declare(strict_types = 1);

namespace Tests\OriNette\Auth\Doubles;

use Orisai\Auth\Authorization\AuthorizationData;
use Orisai\Auth\Authorization\AuthorizationDataBuilder;

final class AuthorizationDataCreator
{

	public function build(): AuthorizationData
	{
		return (new AuthorizationDataBuilder())->build();
	}

}
