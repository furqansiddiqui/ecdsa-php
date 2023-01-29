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

declare(strict_types=1);

namespace FurqanSiddiqui\ECDSA\ECC;

use FurqanSiddiqui\ECDSA\Exception\MathException;

/**
 * Class Math
 * @package FurqanSiddiqui\ECDSA\ECC
 */
class Math
{
    /**
     * @param \GMP $a
     * @param \GMP $p
     * @return array|null
     * @throws \FurqanSiddiqui\ECDSA\Exception\MathException
     */
    public static function gmpSqrt(\GMP $a, \GMP $p): ?array
    {
        if (gmp_legendre($a, $p) !== 1) {
            return null;
        }

        if (gmp_strval(gmp_mod($p, gmp_init(4, 10)), 10) !== '3') {
            throw new MathException("P % 4 != 3 , this isn't supported");
        }

        $sqrt1 = gmp_powm($a, gmp_div_q(gmp_add($p, gmp_init(1, 10)), gmp_init(4, 10)), $p);
        $sqrt2 = gmp_mod(gmp_sub($p, $sqrt1), $p);
        return [$sqrt1, $sqrt2];
    }

    /**
     * @param \GMP $num
     * @param int $n
     * @return \GMP
     */
    public static function gmpShiftRight(\GMP $num, int $n): \GMP
    {
        return gmp_div_q($num, gmp_pow(2, $n));
    }

    /**
     * @param \GMP $num
     * @param int $n
     * @return \GMP
     */
    public static function gmpShiftLeft(\GMP $num, int $n): \GMP
    {
        return gmp_mul($num, gmp_pow(2, $n));
    }
}
