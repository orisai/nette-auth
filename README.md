<h1 align="center">
	<img src="https://github.com/orisai/.github/blob/main/images/repo_title.png?raw=true" alt="Orisai"/>
	<br/>
	Nette Auth
</h1>

<p align="center">
	<a href="https://github.com/orisai/auth">Orisai Auth</a> integration for <a href="https://nette.org">Nette</a>
</p>

<p align="center">
	📄 Check out our <a href="docs/README.md">documentation</a>.
</p>

<p align="center">
	💸 If you like Orisai, please <a href="https://orisai.dev/sponsor">make a donation</a>. Thank you!
</p>

<p align="center">
	<a href="https://github.com/orisai/nette-auth/actions?query=workflow%3ACI">
		<img src="https://github.com/orisai/nette-auth/workflows/CI/badge.svg">
	</a>
	<a href="https://coveralls.io/r/orisai/nette-auth">
		<img src="https://badgen.net/coveralls/c/github/orisai/nette-auth/v1.x?cache=300">
	</a>
	<a href="https://dashboard.stryker-mutator.io/reports/github.com/orisai/nette-auth/v1.x">
		<img src="https://badge.stryker-mutator.io/github.com/orisai/nette-auth/v1.x">
	</a>
	<a href="https://packagist.org/packages/orisai/nette-auth">
		<img src="https://badgen.net/packagist/dt/orisai/nette-auth?cache=3600">
	</a>
	<a href="https://packagist.org/packages/orisai/nette-auth">
		<img src="https://badgen.net/packagist/v/orisai/nette-auth?cache=3600">
	</a>
	<a href="https://choosealicense.com/licenses/mpl-2.0/">
		<img src="https://badgen.net/badge/license/MPL-2.0/blue?cache=3600">
	</a>
<p>

##

```php
namespace App\Admin\Article\View;

use Orisai\Auth\Authentication\Identity;
use Orisai\Auth\Authentication\SimpleFirewall;

final class ArticleEditController
{

	private SimpleFirewall $firewall;

	public function __construct(SimpleFirewall $firewall)
	{
		$this->firewall = $firewall;
	}

	public function run(): void
	{
		if (!$this->firewall->isAllowed('administration.entry')) {
			// Not allowed
		}

		$article = /* get article by ID from request */;

		if (!$this->firewall->isAllowed('article.edit', $article)) {
			// Not allowed
		}

		// Is allowed
	}

}

use App\Core\Article\Article;
use Orisai\Auth\Authorization\Policy;
use Orisai\Auth\Authorization\PolicyContext;

/**
 * @phpstan-implements Policy<Article>
 */
final class ArticleEditPolicy implements Policy
{

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

		return $authorizer->hasPrivilege($identity, self::getPrivilege())
			&& $requirements->getAuthor()->getId() === $identity->getId();
	}

}
```
