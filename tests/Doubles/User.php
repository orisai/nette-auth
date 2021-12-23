<?php declare(strict_types = 1);

namespace Tests\OriNette\Auth\Doubles;

final class User
{

	private int $id;

	public function __construct(int $id)
	{
		$this->id = $id;
	}

	public function getId(): int
	{
		return $this->id;
	}

}
