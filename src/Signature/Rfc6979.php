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

namespace FurqanSiddiqui\ECDSA\Signature;

use Comely\DataTypes\BcNumber;
use Comely\DataTypes\Buffer\Binary;
use Comely\DataTypes\Buffer\Bitwise;
use FurqanSiddiqui\ECDSA\ECC\Math;

/**
 * PHP implementation of RFC6979 deterministic DSA
 * (https://tools.ietf.org/html/rfc6979)
 */

/**
 * Class Rfc6979
 * @package FurqanSiddiqui\ECDSA\Signature
 */
class Rfc6979
{
    /** @var array */
    private const HASH_ALGO = [
        "sha1" => 160,
        "sha256" => 256,
        "sha512" => 512
    ];

    /** @var string */
    private string $algo;
    /** @var BcNumber */
    private BcNumber $privateKey;
    /** @var BcNumber */
    private BcNumber $message;

    /**
     * Rfc6979 constructor.
     * @param string $algo
     * @param BcNumber $message
     * @param BcNumber $privateKey
     */
    public function __construct(string $algo, BcNumber $message, BcNumber $privateKey)
    {
        $this->algo = strtolower($algo);
        if (!array_key_exists($this->algo, self::HASH_ALGO)) {
            throw new \InvalidArgumentException('Invalid/unsupported hash algorithm');
        }

        $this->message = $message;
        $this->privateKey = $privateKey;
    }


    /**
     * @param Bitwise $in
     * @param int $qLen
     * @return BcNumber
     */
    public function bits2int(Bitwise $in, int $qLen): BcNumber
    {
        $vLen = $in->len();
        $v = BcNumber::fromBase16($in->base16());

        if ($vLen > $qLen) {
            $v = Math::bcRightShift($v->value(), $vLen - $qLen);
        }

        return $v;
    }

    /**
     * @param BcNumber $int
     * @param int $roLen
     * @return Binary
     */
    public function int2octets(BcNumber $int, int $roLen): Binary
    {
        $bin = $int->encode()->binary();
        $len = $bin->size()->bytes();

        if ($len < $roLen) {
            return $bin->prepend(str_repeat("\x00", ($roLen - $len)));
        }

        if ($roLen > $len) {
            return $bin->substr(0, $roLen);
        }

        return $bin;
    }

    /**
     * @param BcNumber $q
     * @return BcNumber
     */
    public function generateK(BcNumber $q): BcNumber
    {
        $qBitwise = $q->toBitwise();
        $qLen = $qBitwise->len();
        $hoLen = $this->hashAlgoBitLen();
        $roLen = ($qLen + 7) >> 3;

        $bx = $this->int2octets($this->privateKey, $roLen);
        $bx->append($this->int2octets($this->message, $roLen));

        // Step B
        $v = (new Binary())->append(str_repeat("\x01", $hoLen >> 3));

        // Step C
        $k = (new Binary())->append(str_repeat("\x00", $hoLen >> 3));

        // Step D
        $k = $v->clone()->append("\x00")->append($bx)->hash()->hmac($this->algo, $k);

        // Step E
        $v = $v->clone()->hash()->hmac($this->algo, $k);

        // Step F
        $k = $v->clone()->append("\x01")->append($bx)->hash()->hmac($this->algo, $k);

        // Step G
        $v = $v->clone()->hash()->hmac($this->algo, $k);

        // Step H
        $t = new Binary();
        while (true) {
            // Step H2
            while ($t->size()->bytes() < ($qLen / 8)) {
                /** @var Binary $v */
                $v = $v->clone()->hash()->hmac($this->algo, $k);
                $t->append($v);
            }

            // Step H3
            $secret = $this->bits2int($t->bitwise(), $qLen);
            $secret->scale(0);
            if ($secret->cmp(0) > 0 && $secret->cmp($q) < 0) {
                return $secret;
            }

            $k = $v->clone()->append("\x00")->hash()->hmac($this->algo, $k);
            $v = $v->clone()->hash()->hmac($this->algo, $k);
        }
    }

    /**
     * @return int
     */
    private function hashAlgoBitLen(): int
    {
        return self::HASH_ALGO[$this->algo];
    }
}
