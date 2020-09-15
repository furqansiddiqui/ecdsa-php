<?php
/*
 * This file is a part of "furqansiddiqui/ecdsa-php" package.
 * https://github.com/furqansiddiqui/ecdsa-php
 *
 * Copyright (c) Furqan A. Siddiqui <hello@furqansiddiqui.com>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code or visit following link:
 * https://github.com/furqansiddiqui/ecdsa-php/blob/master/LICENSE
 */

namespace FurqanSiddiqui\ECDSA\ECC;

/**
 * Class Point
 * @package FurqanSiddiqui\ECDSA\ECC
 */
class Point
{
    /** @var AbstractCurve */
    private AbstractCurve $curve;
    /** @var \GMP */
    private $x;
    /** @var \GMP */
    private $y;

    /**
     * Point constructor.
     * @param AbstractCurve $curve
     * @param $x
     * @param $y
     */
    public function __construct(AbstractCurve $curve, $x, $y)
    {
        $this->curve = $curve;
        $this->x = $x instanceof \GMP ? $x : gmp_init($x, 10);
        $this->y = $y instanceof \GMP ? $y : gmp_init($x, 10);
    }

    /**
     * @return array
     */
    public function __debugInfo(): array
    {
        return [
            "x" => $this->x,
            "y" => $this->y
        ];
    }

    /**
     * @return \GMP
     */
    public function x(): \GMP
    {
        return $this->x;
    }

    /**
     * @return \GMP
     */
    public function y(): \GMP
    {
        return $this->y;
    }

    /**
     * @return Point
     */
    public function double(): Point
    {
        $a = $this->curve->a();
        $p = $this->curve->prime();

        if (gmp_strval(gmp_gcd(gmp_mod(gmp_mul(gmp_init(2, 10), $this->y), $p), $p)) !== "1") {
            throw new \LogicException("Point at infinity");
        }

        $t1 = gmp_invert(gmp_mod(gmp_mul(gmp_init(2, 10), $this->y), $p), $p);
        $t2 = gmp_add(gmp_mul(gmp_init(3, 10), gmp_pow($this->x, 2)), $a);
        $slope = gmp_mod(gmp_mul($t1, $t2), $p);

        $nX = gmp_mod(gmp_sub(gmp_sub(gmp_pow($slope, 2), $this->x), $this->x), $p);
        $nY = gmp_mod(gmp_sub(gmp_mul($slope, gmp_sub($this->x, $nX)), $this->y), $p);

        return new Point($this->curve, $nX, $nY);
    }

    /**
     * @param Point $p2
     * @return Point
     */
    public function add(Point $p2): Point
    {
        if (gmp_cmp($this->x, $p2->x()) === 0 && gmp_cmp($this->y, $p2->y()) === 0) {
            return $this->double();
        }

        $p = $this->curve->prime();
        if (gmp_strval(gmp_gcd(gmp_sub($this->x, $p2->x()), $p)) !== "1") {
            throw new \LogicException("Point at infinity");
        }

        $slope = gmp_mod(gmp_mul(gmp_sub($this->y, $p2->y()), gmp_invert(gmp_sub($this->x, $p2->x()), $p)), $p);
        $nX = gmp_mod(gmp_sub(gmp_sub(gmp_pow($slope, 2), $this->x), $p2->x()), $p);
        $nY = gmp_mod(gmp_sub(gmp_mul($slope, gmp_sub($this->x, $nX)), $this->y), $p);

        return new Point($this->curve, $nX, $nY);
    }

    /**
     * @param $k
     * @return Point
     */
    public function mul($k): Point
    {
        $k = gmp_strval($k, 2);
        $mulP = $this;
        for ($i = 1; $i < strlen($k); $i++) {
            if (substr($k, $i, 1) === "1") {
                $d = $mulP->double();
                $mulP = $d->add($this);
            } else {
                $mulP = $mulP->double();
            }
        }

        if (!$mulP->validate()) {
            throw new \UnexpectedValueException('Resulting point not on curve');
        }

        return $mulP;
    }

    /**
     * @return bool
     */
    public function validate(): bool
    {
        $y2 = gmp_mod(gmp_add(gmp_add(gmp_powm($this->x, gmp_init(3, 10), $this->curve->prime()), gmp_mul($this->curve->a(), $this->x)), $this->curve->b()), $this->curve->prime());
        $y = gmp_mod(gmp_pow($this->y, 2), $this->curve->prime());
        return gmp_cmp($y2, $y) === 0;
    }
}
