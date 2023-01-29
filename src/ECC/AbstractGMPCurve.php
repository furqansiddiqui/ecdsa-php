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

namespace FurqanSiddiqui\ECDSA\ECC;

use Comely\Buffer\AbstractByteArray;

/**
 * Class AbstractGMPCurve
 * @package FurqanSiddiqui\ECDSA\ECC
 */
abstract class AbstractGMPCurve implements EllipticCurveInterface
{
    public const A = null;
    public const B = null;
    public const PRIME = null;
    public const ORDER = null;
    public const Gx = null;
    public const Gy = null;

    /** @var \GMP */
    public readonly \GMP $a;
    /** @var \GMP */
    public readonly \GMP $b;
    /** @var \GMP */
    public readonly \GMP $prime;
    /** @var \GMP */
    public readonly \GMP $order;

    /** @var array */
    private static array $instances = [];

    /**
     * @return static
     */
    public static function getInstance(): static
    {
        $curve = get_called_class();
        if (!isset(self::$instances[$curve])) {
            self::$instances[$curve] = new $curve();
        }

        return self::$instances[$curve];
    }

    /**
     * AbstractCurve constructor.
     */
    public function __construct()
    {
        $this->a = gmp_init(static::A, 10);
        $this->b = gmp_init(static::B, 10);
        $this->prime = gmp_init(static::PRIME, 10);
        $this->order = gmp_init(static::ORDER, 10);
    }

    /**
     * @return Point
     */
    public function generator(): Point
    {
        return new Point($this, gmp_init(static::Gx, 10), gmp_init(static::Gy, 10));
    }

    /**
     * @param \GMP|int|string $x
     * @param \GMP|int|string $y
     * @return \FurqanSiddiqui\ECDSA\ECC\Point
     */
    public function getPoint(\GMP|int|string $x, \GMP|int|string $y): Point
    {
        return new Point($this, $x, $y);
    }

    /**
     * @param \Comely\Buffer\AbstractByteArray $privateKey
     * @return \FurqanSiddiqui\ECDSA\ECC\PublicKey
     */
    abstract public function generatePublicKey(AbstractByteArray $privateKey): PublicKey;

    /**
     * @param \Comely\Buffer\AbstractByteArray $compressed
     * @return \FurqanSiddiqui\ECDSA\ECC\PublicKey
     */
    abstract public function getPublicKeyFromCompressed(AbstractByteArray $compressed): PublicKey;

    /**
     * @param \Comely\Buffer\AbstractByteArray $publicKey
     * @return \FurqanSiddiqui\ECDSA\ECC\PublicKey
     */
    abstract public function uncompressedPublicKey(AbstractByteArray $publicKey): PublicKey;
}
