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

use Charcoal\Buffers\AbstractByteArray;
use Charcoal\Buffers\Buffer;
use FurqanSiddiqui\ECDSA\Exception\KeyPairException;

/**
 * Class PublicKey
 * @package FurqanSiddiqui\ECDSA
 */
readonly class PublicKey
{
    /** @var string */
    public string $prefix;

    /**
     * @param \Charcoal\Buffers\AbstractByteArray $publicKey
     * @return static
     * @throws \FurqanSiddiqui\ECDSA\Exception\KeyPairException
     */
    public static function fromDER(AbstractByteArray $publicKey): static
    {
        $bytes = $publicKey->raw();
        if ($bytes[0] === "\x04") {
            if ($publicKey->len() !== 65) {
                throw new KeyPairException('DER public key must be 65 bytes long');
            }

            return new static(bin2hex(substr($bytes, 1, 32)), bin2hex(substr($bytes, 33)));
        }

        throw new KeyPairException('Invalid DER serialized public key');
    }

    /**
     * @param string $x
     * @param string $y
     * @param string|null $compressedPrefix
     */
    public function __construct(
        public string $x,
        public string $y,
        ?string       $compressedPrefix = null,
    )
    {
        if (!$compressedPrefix) {
            $compressedPrefix = gmp_intval(gmp_mod(gmp_init($this->y, 16), 2)) === 0 ? "02" : "03";
        }

        $this->prefix = $compressedPrefix;
    }

    /**
     * @return \Charcoal\Buffers\AbstractByteArray
     */
    public function getUnCompressed(): AbstractByteArray
    {
        return (new Buffer(hex2bin("04" . $this->x . $this->y)))->readOnly();
    }

    /**
     * @return \Charcoal\Buffers\AbstractByteArray
     */
    public function getCompressed(): AbstractByteArray
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
    public function compare(PublicKey $pub2): int
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
