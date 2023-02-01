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
use Comely\Buffer\Bytes32;
use Comely\Buffer\Exception\ByteReaderUnderflowException;
use FurqanSiddiqui\ECDSA\Exception\ECDSA_Exception;
use FurqanSiddiqui\ECDSA\Exception\SignatureException;

/**
 * Class Signature
 * @package FurqanSiddiqui\ECDSA\Signature
 */
class Signature implements SignatureInterface
{
    /**
     * @param \Comely\Buffer\AbstractByteArray $r
     * @param \Comely\Buffer\AbstractByteArray $s
     * @param int $recoveryId
     */
    public function __construct(
        public readonly AbstractByteArray $r,
        public readonly AbstractByteArray $s,
        public readonly int               $recoveryId = -1)
    {
    }

    /**
     * @return array
     */
    public function __debugInfo(): array
    {
        return [
            "r" => $this->r->toBase16(true),
            "s" => $this->s->toBase16(true),
            "v" => $this->recoveryId > -1 ? $this->recoveryId : null
        ];
    }

    /**
     * @param \Comely\Buffer\AbstractByteArray $signature
     * @return static
     * @throws \Comely\Buffer\Exception\ByteReaderUnderflowException
     * @throws \FurqanSiddiqui\ECDSA\Exception\SignatureException
     */
    public static function fromCompact(AbstractByteArray $signature): static
    {
        if ($signature->len() !== 65) {
            throw new SignatureException(sprintf("Compact signatures must be of 65 bytes, got %d", $signature->len()));
        }

        $parse = $signature->read();
        $v = $parse->readUInt8();
        return new static(
            new Bytes32($parse->next(32)),
            new Bytes32($parse->next(32)),
            $v
        );
    }

    /**
     * @param \Comely\Buffer\AbstractByteArray $signature
     * @return static
     * @throws \FurqanSiddiqui\ECDSA\Exception\ECDSA_Exception
     * @throws \FurqanSiddiqui\ECDSA\Exception\SignatureException
     */
    public static function fromDER(AbstractByteArray $signature): static
    {
        try {
            $parse = $signature->read();
            $parse->reset();
            if ($parse->first(1) !== "\x30") {
                throw new SignatureException("Invalid DER signature compound structure");
            }

            $dataLen = $parse->readUInt8();
            if ($signature->len() !== $dataLen + 2) {
                throw new SignatureException("Incomplete signature");
            }

            if ($parse->next(1) !== "\x02") {
                throw new ECDSA_Exception(
                    sprintf('Expected "\x02" byte at position %d, got "\x%s"', $parse->pos(), bin2hex($parse->lookBehind(1)))
                );
            }

            $r = ltrim($parse->next($parse->readUInt8()), "\0");

            if ($parse->next(1) !== "\x02") {
                throw new ECDSA_Exception(
                    sprintf('Expected "\x02" byte at position %d, got "\x%s"', $parse->pos(), bin2hex($parse->lookBehind(1)))
                );
            }

            $s = ltrim($parse->next($parse->readUInt8()), "\0");
        } catch (ByteReaderUnderflowException) {
            throw new SignatureException('Ran out of bytes while parsing DER signature');
        }

        if (!$parse->isEnd()) {
            throw new SignatureException('DER signature contains unnecessary bytes');
        }

        return new static(new Buffer($r), new Buffer($s));
    }

    /**
     * @return \Comely\Buffer\AbstractByteArray
     */
    public function getCompact(): AbstractByteArray
    {
        return (new Buffer(chr($this->recoveryId) . $this->r . $this->s));
    }

    /**
     * @param int $paddedIntegerSize
     * @return \Comely\Buffer\AbstractByteArray
     */
    public function getDER(int $paddedIntegerSize = 0): AbstractByteArray
    {
        // Prepare R
        $r = $this->r->raw();
        if ($paddedIntegerSize > 0 && strlen($r) < $paddedIntegerSize) {
            $r = str_pad($r, $paddedIntegerSize, "\0", STR_PAD_LEFT);
        }

        if (ord($r[0]) >= 0x80) {
            // https://www.oreilly.com/library/view/programming-bitcoin/9781492031482/ch04.html
            $r = "\0" . $r;
        }

        // Prepare S
        $s = $this->s->raw();
        if ($paddedIntegerSize > 0 && strlen($r) < $paddedIntegerSize) {
            $s = str_pad($s, $paddedIntegerSize, "\0", STR_PAD_LEFT);
        }

        if (ord($s[0]) >= 0x80) {
            $s = "\0" . $s;
        }

        // DER Buffer
        $der = new Buffer();
        $der->append("\x02");
        $der->appendUInt8(strlen($r));
        $der->append($r);
        $der->append("\x02");
        $der->appendUInt8(strlen($s));
        $der->append($s);
        $der->prependUInt8($der->len());
        $der->prepend("\x30");
        return $der->readOnly();
    }

    /**
     * Comparison with another Signature instance, primary for cross-lib testings
     * Return values are:
     * 0 = Both signatures are identical
     * -3 = Recovery ids do not match
     * -2 = Signature coordinate S does not match
     * -1 = Signature coordinate R does not match
     * @param \FurqanSiddiqui\ECDSA\Signature\Signature $sig2
     * @return int
     */
    public function compare(Signature $sig2): int
    {
        if (hash_equals($this->r->toBase16(false), $sig2->r->toBase16(false))) {
            if (hash_equals($this->s->toBase16(false), $sig2->s->toBase16(false))) {
                if ($this->recoveryId !== $sig2->recoveryId) {
                    return 0;
                }

                return -3;
            }

            return -2;
        }

        return -1;
    }
}
