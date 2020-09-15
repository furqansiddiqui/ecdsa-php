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

use Comely\DataTypes\Buffer\Base16;

/**
 * Class AbstractCurve
 * @package FurqanSiddiqui\ECDSA\ECC
 */
abstract class AbstractCurve implements EllipticCurveInterface
{
    public const A = null;
    public const B = null;
    public const PRIME = null;
    public const ORDER = null;
    public const Gx = null;
    public const Gy = null;

    /** @var \GMP */
    private $a;
    /** @var \GMP */
    private $b;
    /** @var \GMP */
    private $prime;
    /** @var \GMP */
    private $order;

    /** @var static */
    private static $instances = [];

    /**
     * @return mixed
     */
    public static function getInstance()
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
     * @return \GMP
     */
    public function a(): \GMP
    {
        return $this->a;
    }

    /**
     * @return \GMP
     */
    public function b(): \GMP
    {
        return $this->b;
    }

    /**
     * @return \GMP
     */
    public function prime(): \GMP
    {
        return $this->prime;
    }

    /**
     * @return \GMP
     */
    public function order(): \GMP
    {
        return $this->order;
    }

    /**
     * @return Point
     */
    public function generator(): Point
    {
        return new Point($this, gmp_init(static::Gx, 10), gmp_init(static::Gy, 10));
    }

    /**
     * @param $x
     * @param $y
     * @return Point
     */
    public function getPoint($x, $y): Point
    {
        return new Point($this, $x, $y);
    }

    /**
     * @param Base16 $privateKey
     * @return PublicKey
     */
    abstract public function getPublicKey(Base16 $privateKey): PublicKey;

    /**
     * @param Base16 $compressed
     * @return PublicKey
     */
    abstract public function getPublicKeyFromCompressed(Base16 $compressed): PublicKey;

    /**
     * @param Base16 $publicKey
     * @return PublicKey
     */
    abstract public function usePublicKey(Base16 $publicKey): PublicKey;
}
