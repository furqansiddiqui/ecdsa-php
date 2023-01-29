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

use Comely\Buffer\AbstractByteArray;
use Comely\Buffer\Buffer;
use FurqanSiddiqui\ECDSA\Exception\ECDSA_Exception;

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
    private readonly string $algo;

    /**
     * @param string $algo
     * @param \GMP $message
     * @param \GMP $privateKey
     */
    public function __construct(string $algo, private readonly \GMP $message, private readonly \GMP $privateKey)
    {
        $this->algo = strtolower($algo);
        if (!array_key_exists($this->algo, self::HASH_ALGO)) {
            throw new \InvalidArgumentException('Invalid/unsupported hash algorithm');
        }
    }

    /**
     * @param \GMP $int
     * @param int $roLen
     * @return string
     */
    private function int2octets(\GMP $int, int $roLen): string
    {
        $hex = str_pad(gmp_strval($int, 16), $roLen * 2, "0", STR_PAD_LEFT);
        if (strlen($hex) > $roLen * 2) {
            $hex = substr($hex, 0, $roLen * 2);
        }

        return $hex;
    }

    /**
     * @param \GMP $q
     * @return \Comely\Buffer\AbstractByteArray
     * @throws \FurqanSiddiqui\ECDSA\Exception\ECDSA_Exception
     */
    public function generateK(\GMP $q): AbstractByteArray
    {
        $qLen = strlen(gmp_strval($q, 2));
        $hoLen = static::HASH_ALGO[$this->algo];
        $roLen = ($qLen + 7) >> 3;

        $bx = hex2bin($this->int2octets($this->privateKey, $roLen) .
            $this->int2octets($this->message, $roLen));

        // Step B
        $v = str_repeat("\x01", $hoLen >> 3);

        // Step C
        $k = str_repeat("\x00", $hoLen >> 3);

        // Step D
        $k = hash_hmac($this->algo, $v . "\x00" . $bx, $k, true);

        // Step E
        $v = hash_hmac($this->algo, $v, $k, true);

        // Step F
        $k = hash_hmac($this->algo, $v . "\x01" . $bx, $k, true);

        // Step G
        $v = hash_hmac($this->algo, $v, $k, true);

        // Step H+
        for ($i = 0; $i <= 100; $i++) {
            $v = hash_hmac($this->algo, $v, $k, true);
            $t = gmp_init(bin2hex($v), 16);
            if (gmp_cmp($t, 0) > 0 && gmp_cmp($t, $q) < 0) {
                return Buffer::fromBase16(gmp_strval($t, 16));
            }

            $k = hash_hmac($this->algo, $v . "\x00", $k, true);
            $v = hash_hmac($this->algo, $v, $k, true);
        }

        throw new ECDSA_Exception('Failed to generate RFC6979 randomK value');
    }
}
