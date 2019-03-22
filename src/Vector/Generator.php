<?php
/**
 * This file is a part of "furqansiddiqui/ecdsa-php" package.
 * https://github.com/furqansiddiqui/ecdsa-php
 *
 * Copyright (c) 2019 Furqan A. Siddiqui <hello@furqansiddiqui.com>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code or visit following link:
 * https://github.com/furqansiddiqui/ecdsa-php/blob/master/LICENSE
 */

declare(strict_types=1);

namespace FurqanSiddiqui\ECDSA\Vector;

/**
 * Class Generator
 * @package FurqanSiddiqui\ECDSA\Vector
 */
class Generator
{
    /** @var string */
    private $prime;
    /** @var string */
    private $a;
    /** @var string */
    private $b;

    /**
     * Generator constructor.
     * @param string $prime
     * @param string $a
     * @param string $b
     */
    public function __construct(string $prime, string $a, string $b)
    {
        $this->prime = $prime;
        $this->a = $a;
        $this->b = $b;
    }

    /**
     * @param string $x
     * @param string $y
     * @return bool
     */
    public function has(string $x, string $y): bool
    {
        $mod = bcmod(bcsub(bcpow($y, "2"), bcadd(bcadd(bcpow($x, "3"), bcmul($this->a, $x)), $this->b)), $this->prime);
        return bccomp($mod, "0") === 0 ? true : false;
    }

    /**
     * @return string
     */
    public function a(): string
    {
        return $this->a;
    }

    /**
     * @return string
     */
    public function b(): string
    {
        return $this->b;
    }

    /**
     * @return string
     */
    public function prime(): string
    {
        return $this->prime;
    }

    /**
     * @param Generator $g1
     * @param Generator $g2
     * @return int
     */
    public static function compare(Generator $g1, Generator $g2): int
    {
        return bccomp($g1->a(), $g2->a()) === 0 && bccomp($g1->b(), $g2->b()) === 0 && bccomp($g1->prime(), $g2->prime()) === 0 ? 0 : 1;
    }
}