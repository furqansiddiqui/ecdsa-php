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

use Comely\Buffer\Buffer;

/**
 * Class PublicKey
 * @package FurqanSiddiqui\ECDSA
 */
class PublicKey
{
    /** @var string */
    public readonly string $prefix;

    /**
     * @param string $x
     * @param string $y
     * @param string|null $compressedPrefix
     */
    public function __construct(
        public readonly string $x,
        public readonly string $y,
        ?string                $compressedPrefix = null,
    )
    {

        $this->prefix = !$compressedPrefix ?
            gmp_strval(gmp_mod(gmp_init($this->y, 16), gmp_init(2, 10))) === "0" ? "02" : "03" : $compressedPrefix;
    }

    /**
     * @return \Comely\Buffer\Buffer
     */
    public function getUnCompressed(): Buffer
    {
        return (new Buffer(hex2bin("04" . $this->x . $this->y)))->readOnly();
    }

    /**
     * @return \Comely\Buffer\Buffer
     */
    public function getCompressed(): Buffer
    {
        return (new Buffer(hex2bin($this->prefix . $this->x)))->readOnly();
    }

    /**
     * Comparison with another Public key instance, i.e. compare a signature recovered public key.
     * Return values are:
     * 0 = Both public keys are identical
     * -3 = Compressed prefix does not match (between 02 and 03)
     * -2 = Public key Y does not match
     * -1 = Public key X does not match
     * @param \FurqanSiddiqui\ECDSA\ECC\PublicKey $pub2
     * @return int
     */
    public function verifyMatch(PublicKey $pub2): int
    {
        if (hash_equals($this->x, $pub2->x)) {
            if (hash_equals($this->y, $pub2->y)) {
                if (hash_equals($this->prefix, $pub2->prefix)) {
                    return 0;
                }

                return -3;
            }

            return -2;
        }

        return -1;
    }
}
