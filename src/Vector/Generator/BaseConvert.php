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

/**
 * Class BaseConvert
 * @package FurqanSiddiqui\ECDSA\Vector\Generator
 */
class BaseConvert
{
    /**
     * @param string $val
     * @param int $base
     * @param string|null $charset
     * @return string
     */
    public static function ToDec(string $val, int $base, ?string $charset = null): string
    {
        if (!$charset) {
            $charset = self::charset($base);
        }

        $result = "0";
        $baseIsStr = strval($base);
        $val = $base < 37 ? strtolower($val) : $val;
        $size = strlen($val);
        for ($i = 0; $i < $size; $i++) {
            $digit = strpos($charset, $val[$i]);
            $result = bcadd($result, bcmul(strval($digit), bcpow($baseIsStr, strval(($size - $i) - 1), 0), 0), 0);
        }

        return $result;
    }

    /**
     * @param string $dec
     * @param int $base
     * @param string|null $charset
     * @return string
     */
    public static function FromDec(string $dec, int $base, ?string $charset = null): string
    {
        if (!$charset) {
            $charset = self::charset($base);
        }

        $result = "";
        $baseIsStr = strval($base);
        while (bccomp($dec, bcsub($baseIsStr, "1")) === 1) {
            $charIndex = bcmod($dec, $baseIsStr, 0);
            $dec = bcdiv($dec, $baseIsStr, 0);
            $result = $charset[intval($charIndex)] . $result;
        }

        return $charset[intval($dec)] . $result;
    }

    /**
     * @param int $base
     * @return string
     */
    private static function charset(int $base): string
    {
        $charset = "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ-_";
        if ($base > 64) {
            $charset = "";
            for ($i = 0; $i < 256; $i++) {
                $charset .= chr($i);
            }
        }

        return substr($charset, 0, $base);
    }
}