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

namespace FurqanSiddiqui\ECDSA\Curves\Secp256k1;

use FurqanSiddiqui\BcMath\BcNumber;
use FurqanSiddiqui\DataTypes\Binary;
use FurqanSiddiqui\ECDSA\Curves\AbstractCurve;
use FurqanSiddiqui\ECDSA\PublicKey;
use FurqanSiddiqui\ECDSA\Signature;
use FurqanSiddiqui\ECDSA\Vector;
use FurqanSiddiqui\ECDSA\Vector\Coordinates;
use FurqanSiddiqui\ECDSA\Vector\Generator;
use FurqanSiddiqui\ECDSA\Vector\Generator\Math;
use FurqanSiddiqui\ECDSA\Vector\Generator\Point;

/**
 * Class Secp256k1
 * @package FurqanSiddiqui\ECDSA\Curves\Secp256k1
 */
class Secp256k1 extends AbstractCurve implements Secp256k1Constants
{
    protected const NAME = "secp256k1";

    /** @var BcNumber */
    protected $prime;
    /** @var BcNumber */
    protected $order;
    /** @var Coordinates */
    protected $coords;

    /**
     * Secp256k1 constructor.
     * @throws \FurqanSiddiqui\ECDSA\Exception\GenerateVectorException
     */
    public function __construct()
    {
        $this->prime = BcNumber::fromBase16String(static::PRIME)->scale(0);
        $this->order = BcNumber::fromBase16String(self::ORDER)->scale(0);
        $this->coords = new Coordinates();
        foreach (self::COORDINATES as $point => $num) {
            $this->coords->set($point, BcNumber::fromBase16String($num)->scale(0));
        }
    }

    /**
     * @param Binary $privateKey
     * @return Vector
     * @throws \FurqanSiddiqui\ECDSA\Exception\GenerateVectorException
     * @throws \FurqanSiddiqui\ECDSA\Exception\MathException
     */
    public function vectorFromPrivateKey(Binary $privateKey): Vector
    {
        $generator = new Generator($this->prime->value(), $this->coords->get("a")->value(), $this->coords->get("b")->value());
        $initialPoint = new Point($generator, $this->coords->x()->value(), $this->coords->y()->value(), $this->order->value());
        $point = Point::mul(Math::bin2dec("\x00" . $privateKey->raw()), $initialPoint);

        $coords = new Coordinates();
        $coords->set("x", new BcNumber($point->x()));
        $coords->set("y", new BcNumber($point->y()));

        $vector = new Vector($this, $coords);
        $vector->setBcNumber("prime", $this->prime);
        $vector->setBcNumber("order", $this->order);
        return $vector;
    }

    /**
     * @param Binary $privateKey
     * @return PublicKey
     * @throws \FurqanSiddiqui\ECDSA\Exception\GenerateVectorException
     * @throws \FurqanSiddiqui\ECDSA\Exception\MathException
     */
    public function publicKeyFromPrivateKey(Binary $privateKey): PublicKey
    {
        $vector = $this->vectorFromPrivateKey($privateKey);
        return PublicKey::PublicKeyFromVector($vector);
    }

    /**
     * @param Binary $privateKey
     * @param Binary $msgHash
     * @param Binary $randomK
     * @return Signature
     * @throws \FurqanSiddiqui\ECDSA\Exception\GenerateVectorException
     * @throws \FurqanSiddiqui\ECDSA\Exception\MathException
     */
    public function sign(Binary $privateKey, Binary $msgHash, ?Binary $randomK = null): Signature
    {
        if ($privateKey->size()->bytes() !== 32) {
            throw new \LengthException('Private key must be 32 bytes long');
        }

        if ($randomK) {
            $randomK = BcNumber::Decode($randomK->encode()->base16());
        } else {
            $randomK = new Signature\Rfc6979(
                "sha256",
                BcNumber::Decode($msgHash->encode()->base16()),
                BcNumber::Decode($privateKey->encode()->base16())
            );
        }

        $generator = new Generator($this->prime->value(), $this->coords->get("a")->value(), $this->coords->get("b")->value());
        $initialPoint = new Point($generator, $this->coords->x()->value(), $this->coords->y()->value(), $this->order->value());

        $modulus = $this->order->value();
        $privateKeyInt = BcNumber::Decode($privateKey->encode()->base16())->scale(0);
        $msgHashInt = BcNumber::Decode($msgHash->encode()->base16())->scale(0);
        $k = $randomK->mod($modulus);
        $p1 = Point::mul($k->value(), $initialPoint);
        $r = (new BcNumber($p1->x()))->scale(0);
        if ($r->isZero()) {
            throw new \UnexpectedValueException('Signature point "R" is not positive');
        }

        $s = bcmul($privateKeyInt->value(), $r->value(), 0);
        $s = bcmod(bcadd($msgHashInt->value(), $s, 0), $modulus, 0);
        $s2 = Math::inverseMod($k->value(), $modulus);
        $s = bcmod(bcmul($s, $s2, 0), $modulus, 0);
        $s = (new BcNumber($s))->scale(0);
        if ($s->isZero()) {
            throw new \UnexpectedValueException('Signature point "S" is not positive');
        }

        // If s is less than half the curve order, invert s
        $rightShiftedOrder = Math::rightShift($this->order->value(), 1);
        if ($s->greaterThanOrEquals($rightShiftedOrder) || $s->isZero()) {
            $s = $this->order->sub($s);
        }

        return new Signature($r->encode()->binary(), $s->encode()->binary());
    }
}