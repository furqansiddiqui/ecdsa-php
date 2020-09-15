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

/**
 * Class Math
 * @package FurqanSiddiqui\ECDSA\ECC
 */
class Math
{
    /**
     * @param $a
     * @param $p
     * @return array|null
     */
    public static function sqrt($a, $p): ?array
    {
        if (gmp_legendre($a, $p) !== 1) {
            return null;
        }

        if (gmp_strval(gmp_mod($p, gmp_init(4, 10)), 10) !== '3') {
            throw new \LogicException("P % 4 != 3 , this isn't supported");
        }

        $sqrt1 = gmp_powm($a, gmp_div_q(gmp_add($p, gmp_init(1, 10)), gmp_init(4, 10)), $p);
        $sqrt2 = gmp_mod(gmp_sub($p, $sqrt1), $p);
        return [$sqrt1, $sqrt2];
    }

    public static function bcRightShift(string $num, int $pos): string
    {
        return bcdiv($num, bcpow("2", strval($pos), 0), 0);
    }

    /**
     * @param string $num
     * @param int $pos
     * @return string
     */
    public static function bcLeftShift(string $num, int $pos): string
    {
        return bcmul($num, bcpow("2", strval($pos), 0), 0);
    }
}
