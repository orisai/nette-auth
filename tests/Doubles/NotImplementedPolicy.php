<?php declare(strict_types = 1);

namespace Tests\OriNette\Auth\Doubles;

use Orisai\Auth\Authorization\Policy;

/**
 * @template T of object
 * @implements Policy<T>
 */
abstract class NotImplementedPolicy implements Policy
{

}
