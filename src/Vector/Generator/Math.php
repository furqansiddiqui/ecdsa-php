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

use FurqanSiddiqui\ECDSA\Exception\MathException;

/**
 * Class Math
 * @package FurqanSiddiqui\ECDSA\Vector\Generator
 */
class Math
{
    /**
     * @param $val
     * @return string|null
     */
    public static function getIntegral($val): ?string
    {
        return self::isIntegral($val) ? strval($val) : null;
    }

    /**
     * @param $val
     * @return bool
     */
    public static function isIntegral($val): bool
    {
        switch (gettype($val)) {
            case "integer":
                return true;
            case "string":
                return preg_match('/^[0-9]+$/', $val) ? true : false;
            default:
                return false;
        }
    }

    /**
     * @param string $a
     * @param string $m
     * @return string
     * @throws MathException
     */
    public static function inverseMod(string $a, string $m)
    {
        while (bccomp($a, "0") == -1) {
            $a = bcadd($m, $a);
        }

        while (bccomp($m, $a) == -1) {
            $a = bcmod($a, $m);
        }

        $c = $a;
        $d = $m;
        $uc = "1";
        $vc = "0";
        $ud = "0";
        $vd = "1";
        while (bccomp($c, "0") !== 0) {
            $temp1 = $c;
            $q = bcdiv($d, $c, 0);
            $c = bcmod($d, $c);
            $d = $temp1;
            $temp2 = $uc;
            $temp3 = $vc;
            $uc = bcsub($ud, bcmul($q, $uc));
            $vc = bcsub($vd, bcmul($q, $vc));
            $ud = $temp2;
            $vd = $temp3;
        }

        if (bccomp($d, "1") !== 0) {
            throw new MathException('Both arguments are must be co-prime');
        }

        return bccomp($ud, "0") === 1 ? $ud : bcadd($ud, $m);
    }

    /**
     * @param $x
     * @param $y
     * @return string
     */
    public static function And($x, $y)
    {
        return self::bitwiseCallback($x, $y, function ($a, $b) {
            return $a & $b;
        });
    }

    /**
     * @param string $a
     * @param string $b
     * @param callable $callback
     * @return string
     */
    protected static function bitwiseCallback(string $a, string $b, callable $callback)
    {
        $a = self::dec2bin($a);
        $b = self::dec2bin($b);
        self::binPadEqual($a, $b);

        $res = "";
        for ($i = 0; $i < strlen($b); $i++) {
            $res .= call_user_func_array($callback, [substr($a, $i, 1), substr($b, $i, 1)]);
        }

        return self::bin2dec($res);
    }

    /**
     * @param $num
     * @return string
     */
    public static function dec2bin($num)
    {
        return BaseConvert::FromDec(strval($num), 256);
    }

    /**
     * @param $num
     * @return string
     */
    public static function bin2dec($num)
    {
        return BaseConvert::ToDec(strval($num), 256);
    }

    /**
     * @param $a
     * @param $b
     */
    public static function binPadEqual(string &$a, string &$b)
    {
        $len = max(strlen($a), strlen($b));
        self::binPadFixed($a, $len);
        self::binPadFixed($b, $len);
    }

    /**
     * @param string $var
     * @param int $length
     */
    public static function binPadFixed(string &$var, int $length)
    {
        $pad = "";
        for ($i = 0; $i < $length - strlen($var); $i++) {
            $pad .= self::dec2bin("0");
        }

        $var = $pad . $var;
    }
}