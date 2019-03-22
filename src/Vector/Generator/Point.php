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

namespace FurqanSiddiqui\ECDSA\Vector\Generator;

use FurqanSiddiqui\ECDSA\Exception\GenerateVectorException;
use FurqanSiddiqui\ECDSA\Vector\Generator;

/**
 * Class Point
 * @package FurqanSiddiqui\ECDSA\Vector\Generator
 */
class Point
{
    /** @var Generator */
    private $generator;
    /** @var string */
    private $x;
    /** @var string */
    private $y;
    /** @var string|null */
    private $order;

    /** @var string */
    public static $infinity = "infinity";

    /**
     * Point constructor.
     * @param Generator $generator
     * @param string $x
     * @param string $y
     * @param string|null $order
     * @throws GenerateVectorException
     */
    public function __construct(Generator $generator, string $x, string $y, ?string $order = null)
    {
        $this->generator = $generator;
        $this->x = $x;
        $this->y = $y;
        $this->order = $order;

        if (!$this->generator->has($this->x, $this->y)) {
            throw new GenerateVectorException(
                sprintf('Curve does not contain point ("%s","%s")', $this->x, $this->y)
            );
        }

        if ($this->order) {
            if (self::compare(self::mul($order, $this), self::$infinity) !== 0) {
                throw new GenerateVectorException("SELF * ORDER MUST EQUAL INFINITY.");
            }
        }
    }

    /**
     * @param $p1
     * @param $p2
     * @return int
     */
    public static function compare($p1, $p2)
    {
        if (!$p1 instanceof Point) {
            return $p2 instanceof Point ? 1 : 0;
        }

        if (!$p2 instanceof Point) {
            return $p1 instanceof Point ? 1 : 0;
        }

        return bccomp($p1->x, $p2->x) == 0 && bccomp($p1->y, $p2->y) == 0 && Generator::compare($p1->generator(), $p2->generator()) ? 0 : 1;
    }

    /**
     * @param Point $p1
     * @param Point $p2
     * @return Point|string
     * @throws GenerateVectorException
     * @throws \FurqanSiddiqui\ECDSA\Exception\MathException
     */
    public static function add(Point $p1, Point $p2)
    {
        if (Generator::compare($p1->generator(), $p2->generator()) !== 0) {
            throw new GenerateVectorException("Generator points do not match");
        }

        if (bcmod(strval(bccomp($p1->x, $p2->x)), $p1->generator()->prime()) == 0) {
            return bcmod(bcadd($p1->y, $p2->y), $p1->generator()->prime()) == 0 ?
                self::$infinity : self::double($p1);
        }

        $p = $p1->generator()->prime();
        $l = bcmod(bcmul(bcsub($p2->y, $p1->y), Math::inverseMod(bcsub($p2->x, $p1->x), $p)), $p);
        $x3 = bcmod(bcsub(bcsub(bcpow($l, "2"), $p1->x), $p2->x), $p);
        $y3 = bcmod(bcsub(bcmul($l, bcsub($p1->x, $x3)), $p1->y), $p);
        if (bccomp("0", $y3) == 1) {
            $y3 = bcadd($p, $y3);
        }

        return new Point($p1->generator(), $x3, $y3);
    }

    /**
     * @param $x2
     * @param Point $p1
     * @return Point|string|null
     * @throws GenerateVectorException
     * @throws \FurqanSiddiqui\ECDSA\Exception\MathException
     */
    public static function mul($x2, Point $p1)
    {
        $result = null;
        $e = $x2;

        if (self::compare($p1, self::$infinity) == 0) {
            return self::$infinity;
        }

        if ($p1->order()) {
            $e = bcmod($e, $p1->order());
        }

        if (bccomp($e, "0") == 0) {
            return self::$infinity;
        }

        if (bccomp($e, "0") == 1) {
            $e3 = bcmul("3", $e);
            $negative_self = new Point($p1->generator(), $p1->x, bcsub("0", $p1->y), $p1->order);
            $i = bcdiv(self::leftmostBit($e3), "2");
            $result = $p1;
            while (bccomp($i, "1") == 1) {
                $result = self::double($result);
                if (bccomp(Math::And($e3, $i), "0") !== 0 && bccomp(Math::And($e, $i), "0") === 0) {
                    $result = self::add($result, $p1);
                }

                if (bccomp(Math::And($e3, $i), "0") === 0 && bccomp(Math::And($e, $i), "0") !== 0) {
                    $result = self::add($result, $negative_self);
                }

                $i = bcdiv($i, "2");
            }
        }

        return $result;
    }

    /**
     * @param string $x
     * @return string|null
     * @throws GenerateVectorException
     */
    public static function leftmostBit(string $x)
    {
        if (bccomp($x, "0") == 1) {
            $result = "1";
            while (bccomp($result, $x) == -1 || bccomp($result, $x) == 0) {
                $result = bcmul("2", $result);
            }

            return bcdiv($result, "2");
        }

        throw new GenerateVectorException('Failed to get left most bit');
    }

    /**
     * @param Point $point
     * @return Point
     * @throws GenerateVectorException
     * @throws \FurqanSiddiqui\ECDSA\Exception\MathException
     */
    public static function double(Point $point)
    {
        $prime = $point->generator()->prime();
        $pointA = $point->generator()->a();
        $inverse = Math::inverseMod(bcmul("2", $point->y()), $prime);
        $modPrime = bcmod(bcmul(bcadd(bcmul("3", bcpow($point->x(), "2")), $pointA), $inverse), $prime);
        $modX = bcmod(bcsub(bcpow($modPrime, "2"), bcmul("2", $point->x())), $prime);
        $modY = bcmod(bcsub(bcmul($modPrime, bcsub($point->x(), $modX)), $point->y()), $prime);
        if (bccomp("0", $modY) == 1) {
            $modY = bcadd($prime, $modY);
        }

        return new Point($point->generator(), $modX, $modY);
    }

    /**
     * @return string
     */
    public function x(): string
    {
        return $this->x;
    }

    /**
     * @return string
     */
    public function y(): string
    {
        return $this->y;
    }

    /**
     * @return Generator
     */
    public function generator(): Generator
    {
        return $this->generator;
    }

    /**
     * @return string|null
     */
    public function order(): ?string
    {
        return $this->order;
    }
}