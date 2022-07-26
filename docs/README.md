# Nette Auth

[Orisai Auth](https://github.com/orisai/auth) integration for [Nette](https://nette.org)

> This is just an integration into Nette. For full documentation, check [orisai/auth](https://github.com/orisai/auth).

## Content

- [Setup](#setup)
- [Authentication](#authentication)
- [Authorization](#authorization)
- [Passwords](#passwords)
- [Debug mode](#debug-mode)

## Setup

Install with [Composer](https://getcomposer.org)

```sh
composer require orisai/nette-auth
```

```neon
extensions:
	orisai.auth: OriNette\Auth\DI\AuthExtension
```

## Authentication

> Firewall usage is described by [orisai/auth](https://github.com/orisai/auth) documentation.

Register your firewall.

- choose a unique namespace for your storage
- create and register identity refresher
- choose where data should be stored - `ArrayLoginStorage` and `SessionLoginStorage` are registered by extension

```neon
services:
	firewall:
		factory: Orisai\Auth\Authentication\SimpleFirewall
		arguments:
			namespace: admin
			refresher: App\Auth\IdentityRefresher()
			storage: @OriNette\Auth\Http\SessionLoginStorage
```

```php
namespace App\Auth;

use Orisai\Auth\Authentication\IdentityRefresher;

final class AdminIdentityRefresher implements IdentityRefresher
{

	// Implementation is described by orisai/auth docs

}
```

## Authorization

> Authorizer usage, policies and authorization data building are described
> by [orisai/auth](https://github.com/orisai/auth) documentation.

Extension registers authorizer for us, we just have to provide authorization data:

```neon
orisai.auth:
	authorization:
		dataCreator: @creator

services:
	creator: App\Auth\AuthorizationDataCreatorImpl
```

```php
namespace App\Auth;

use Orisai\Auth\Authorization\AuthorizationData;
use Orisai\Auth\Authorization\AuthorizationDataBuilder;
use Orisai\Auth\Authorization\AuthorizationDataCreator;

final class AuthorizationDataCreatorImpl implements AuthorizationDataCreator
{

	public function create(): AuthorizationData
	{
		$builder = new AuthorizationDataBuilder();

		// Add all roles and privileges, as described by orisai/auth docs

		return $builder->build();
	}

}
```

Policies have to be registered as services:

```neon
services:
	- App\Auth\ExamplePolicy
```

## Passwords

> PasswordEncoder usage is described by [orisai/auth](https://github.com/orisai/auth) documentation.

Extension registers a `PasswordEncoder`. Default one uses argon2id algorithm.

## Debug mode

To show firewalls, identities and privileges in Tracy panel, enable `debug > panel` option.

```neon
orisai.auth:
	debug:
		panel: %debugMode%
```
