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

namespace FurqanSiddiqui\ECDSA\Curves;

use FurqanSiddiqui\DataTypes\Base16;
use FurqanSiddiqui\ECDSA\ECC\AbstractCurve;
use FurqanSiddiqui\ECDSA\ECC\Math;
use FurqanSiddiqui\ECDSA\ECC\PublicKey;

/**
 * Class Secp256k1
 * @package FurqanSiddiqui\ECDSA\Curves
 */
class Secp256k1 extends AbstractCurve
{
    public const OID = "1.3.132.0.10";

    public const A = "0";
    public const B = "7";
    public const PRIME = "115792089237316195423570985008687907853269984665640564039457584007908834671663";
    public const ORDER = "115792089237316195423570985008687907852837564279074904382605163141518161494337";
    public const Gx = "55066263022277343669578718895168534326250603453777594175500187360389116729240";
    public const Gy = "32670510020758816978083085130507043184471273380659243275938904335757337482424";

    /**
     * @param Base16 $privateKey
     * @return PublicKey
     */
    public function getPublicKey(Base16 $privateKey): PublicKey
    {
        $publicKey = $this->generator()->mul(gmp_init($privateKey->hexits(), 16));
        $kX = new Base16(gmp_strval($publicKey->x(), 16));
        if ($kX->size()->chars() < 64) {
            $kX->prepend(str_repeat("0", 64 - $kX->size()->chars()));
        }

        $kY = new Base16(gmp_strval($publicKey->y(), 16));
        if ($kY->size()->chars() < 64) {
            $kY->prepend(str_repeat("0", 64 - $kX->size()->chars()));
        }

        return new PublicKey($kX, $kY);
    }

    /**
     * @param Base16 $compressed
     * @return PublicKey
     */
    public function getPublicKeyFromCompressed(Base16 $compressed): PublicKey
    {
        $a = $this->a();
        $b = $this->b();
        $p = $this->prime();

        $evenOrOddPrefix = null;
        $x = $compressed->hexits();
        if (strlen($x) !== 66) {
            throw new \LengthException('Invalid public key length');
        }

        $evenOrOddPrefix = substr($x, 0, 2);
        $x = gmp_init(substr($x, 2), 16);
        $y2 = gmp_mod(gmp_add(gmp_add(gmp_powm($x, gmp_init(3, 10), $p), gmp_mul($a, $x)), $b), $p);
        $y = Math::sqrt($y2, $p);
        if (!$y) {
            throw new \UnexpectedValueException('Failed to calculate point Y');
        }

        if ($evenOrOddPrefix === "02") {
            $resY = null;
            if (gmp_strval(gmp_mod($y[0], gmp_init(2, 10)), 10) === '0') {
                $resY = gmp_strval($y[0], 16);
            }

            if (gmp_strval(gmp_mod($y[1], gmp_init(2, 10)), 10) === '0') {
                $resY = gmp_strval($y[1], 16);
            }

            if ($resY !== null) {
                while (strlen($resY) < 64) {
                    $resY = '0' . $resY;
                }
            }

            return new PublicKey(new Base16(gmp_strval($x, 16)), new Base16($resY));
        } elseif ($evenOrOddPrefix === "03") {
            $resY = null;
            if (gmp_strval(gmp_mod($y[0], gmp_init(2, 10)), 10) === '1') {
                $resY = gmp_strval($y[0], 16);
            }

            if (gmp_strval(gmp_mod($y[1], gmp_init(2, 10)), 10) === '1') {
                $resY = gmp_strval($y[1], 16);
            }

            if ($resY !== null) {
                while (strlen($resY) < 64) {
                    $resY = '0' . $resY;
                }
            }

            return new PublicKey(new Base16(gmp_strval($x, 16)), new Base16($resY));
        }

        throw new \InvalidArgumentException('Invalid even or odd prefix');
    }

    /**
     * @param Base16 $publicKey
     * @return PublicKey
     */
    public function usePublicKey(Base16 $publicKey): PublicKey
    {
        $publicKey = $publicKey->hexits();
        if (strlen($publicKey) !== 130) {
            throw new \LengthException('DER public key must be 65 byte long');
        }

        $prefix = substr($publicKey, 0, 2);
        if ($prefix !== "04") {
            throw new \InvalidArgumentException('DER public key prefix must be "04"');
        }

        return new PublicKey(new Base16(substr($publicKey, 2, 64)), new Base16(substr($publicKey, 66)));
    }
}