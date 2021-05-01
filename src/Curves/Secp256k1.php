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

namespace FurqanSiddiqui\ECDSA\Curves;

use Comely\DataTypes\BcNumber;
use Comely\DataTypes\Buffer\Base16;
use FurqanSiddiqui\ECDSA\ECC\AbstractCurve;
use FurqanSiddiqui\ECDSA\ECC\Math;
use FurqanSiddiqui\ECDSA\ECC\PublicKey;
use FurqanSiddiqui\ECDSA\Signature\Rfc6979;
use FurqanSiddiqui\ECDSA\Signature\Signature;
use FurqanSiddiqui\ECDSA\Signature\SignatureInterface;

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
        if ($kX->len() < 64) {
            $kX->prepend(str_repeat("0", 64 - $kX->len()));
        }

        $kY = new Base16(gmp_strval($publicKey->y(), 16));
        if ($kY->len() < 64) {
            $kY->prepend(str_repeat("0", 64 - $kY->len()));
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

        $resY = null;
        if ($evenOrOddPrefix === "02") {
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

    /**
     * @param Base16 $privateKey
     * @param Base16 $msgHash
     * @param Base16|null $randomK
     * @return Signature
     */
    public function sign(Base16 $privateKey, Base16 $msgHash, ?Base16 $randomK = null): Signature
    {
        $n = $this->order();
        $privateKeyInt = gmp_init($privateKey->hexits(), 16);
        $msgHashInt = gmp_init($msgHash->hexits(), 16);

        // use specified K or use Deterministic RNG
        if (!$randomK) {
            // RFC6979
            $rfc6979 = new Rfc6979("sha256", new BcNumber(gmp_strval($msgHashInt, 10)), new BcNumber(gmp_strval($privateKeyInt, 10)));
            $randomK = $rfc6979->generateK(new BcNumber(gmp_strval($n, 10)))->encode();
        }

        $randomKInt = gmp_init($randomK->hexits(), 16);

        // First part of the signature (R).
        $generator = $this->generator();
        $ptR = $generator->mul($randomKInt);
        $r = gmp_strval($ptR->x(), 16);
        while (strlen($r) < 64) {
            $r = "0" . $r;
        }

        // Second part of the signature (S).
        $s = gmp_mod(gmp_mul(gmp_invert($randomKInt, $n), gmp_add($msgHashInt, gmp_mul($privateKeyInt, gmp_init($r, 16)))), $n);

        // BIP 62, make sure we use the low-s value
        if (gmp_cmp($s, gmp_div($n, 2)) === 1) {
            $s = gmp_sub($n, $s);
        }

        // Event out hexits on S
        $s = gmp_strval($s, 16);
        if (strlen($s) % 2) {
            $s = "0" . $s;
        }

        // Even out hexits on R
        if (strlen($r) % 2) {
            $r = "0" . $r;
        }

        return new Signature(new Base16($r), new Base16($s), $ptR, $randomK);
    }

    /**
     * @param PublicKey $publicKey
     * @param SignatureInterface $signature
     * @param Base16 $msgHash
     * @return bool
     */
    public function verify(PublicKey $publicKey, SignatureInterface $signature, Base16 $msgHash): bool
    {
        $G = $this->generator();
        $R = $signature->r()->hexits();
        $S = $signature->s()->hexits();
        $hash = $msgHash->hexits();

        $exp1 = gmp_mul(gmp_invert(gmp_init($S, 16), $this->order()), gmp_init($hash, 16));
        $exp1Pt = $G->mul($exp1);
        $exp2 = gmp_mul(gmp_invert(gmp_init($S, 16), $this->order()), gmp_init($R, 16));

        $pubKeyPt = $this->getPoint(
            gmp_init($publicKey->x()->hexits(), 16),
            gmp_init($publicKey->y()->hexits(), 16)
        );

        $exp2Pt = $pubKeyPt->mul($exp2);
        $resultPt = $exp1Pt->add($exp2Pt);
        $resultX = gmp_strval($resultPt->x(), 16);
        while (strlen($resultX) < 64) {
            $resultX = "0" . $resultX;
        }

        return hash_equals(strtoupper($resultX), strtoupper($R));
    }

    /**
     * @param SignatureInterface $signature
     * @param Base16 $msgHash
     * @param int $flag
     * @return PublicKey
     */
    public function recoverPublicKeyFromSignature(SignatureInterface $signature, Base16 $msgHash, int $flag): PublicKey
    {
        $R = $signature->r()->hexits();
        $S = $signature->s()->hexits();
        $msgHashInt = gmp_init($msgHash->hexits(), 16);

        if ($flag < 27 || $flag >= 35) {
            throw new \InvalidArgumentException('Invalid flag');
        }

        if ($flag >= 31) {
            $flag -= 4;
        }

        $recId = $flag - 27;

        // Step 1.1
        $x = gmp_add(gmp_init($R, 16), gmp_mul($this->order(), gmp_div_q(gmp_init($recId, 10), gmp_init(2, 10))));

        // Step 1.3
        $preY = $flag % 2 === 1 ? "02" : "03";
        try {
            $yPubKey = $this->getPublicKeyFromCompressed((new Base16(gmp_strval($x, 16)))->prepend($preY));
            $y = gmp_init($yPubKey->y()->hexits(), 16);
        } catch (\Exception $e) {
            throw new \UnexpectedValueException('Could not retrieve public key Y');
        }

        $ptR = $this->getPoint($x, $y);

        // Step 1.6.1
        $eG = $this->generator()->mul($msgHashInt);
        $eGY = gmp_mod(gmp_neg($eG->y()), $this->prime());
        $eG = $this->getPoint($eG->x(), $eGY);
        $SR = $ptR->mul(gmp_init($S, 16));
        $SReG = $SR->add($eG);
        $pubKey = $SReG->mul(gmp_invert(gmp_init($R, 16), $this->order()));
        $pubKeyX = gmp_strval($pubKey->x(), 16);
        while (strlen($pubKeyX) < 64) {
            $pubKeyX = "0" . $pubKeyX;
        }

        $pubKeyY = gmp_strval($pubKey->y(), 16);
        while (strlen($pubKeyY) < 64) {
            $pubKeyY = "0" . $pubKeyY;
        }

        $publicKey = new PublicKey(new Base16($pubKeyX), new Base16($pubKeyY));
        if ($this->verify($publicKey, $signature, $msgHash)) {
            return $publicKey;
        }

        throw new \RuntimeException('Public key cannot be recovered with given arguments');
    }

    /**
     * @param PublicKey $publicKey
     * @param Signature $signature
     * @param Base16 $msgHash
     * @param bool $compressed
     * @return int
     */
    public function findRecoveryId(PublicKey $publicKey, Signature $signature, Base16 $msgHash, bool $compressed): int
    {
        $matchPubKeyHex = $compressed ? $publicKey->getCompressed() : $publicKey->getUnCompressed();
        $matchPubKeyHex = $matchPubKeyHex->hexits();

        $finalFlag = 0;
        for ($i = 0; $i < 4; $i++) {
            $flag = 27;
            if ($compressed === true) {
                $flag += 4;
            }

            $flag += $i;
            try {
                $recoveredPubKey = $this->recoverPublicKeyFromSignature($signature, $msgHash, $flag);
            } catch (\Exception $e) {
            }

            if (isset($recoveredPubKey)) {
                $recPubKeyHex = $compressed ? $recoveredPubKey->getCompressed() : $recoveredPubKey->getUnCompressed();
                $recPubKeyHex = $recPubKeyHex->hexits();
                if (hash_equals($matchPubKeyHex, $recPubKeyHex)) {
                    $finalFlag = $flag;
                    break;
                }
            }
        }

        if ($finalFlag) {
            return $finalFlag;
        }

        throw new \RuntimeException('Could not find valid recovery Id for signature');
    }
}
