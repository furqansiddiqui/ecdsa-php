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
    private $prime;
    /** @var BcNumber */
    private $order;
    /** @var Coordinates */
    private $coords;

    /**
     * Secp256k1 constructor.
     * @throws \FurqanSiddiqui\ECDSA\Exception\GenerateVectorException
     */
    public function __construct()
    {
        $this->prime = BcNumber::Decode(self::PRIME);
        $this->order = BcNumber::Decode(self::ORDER);
        $this->coords = new Coordinates();
        foreach (self::COORDINATES as $point => $num) {
            $this->coords->set($point, BcNumber::Decode($num));
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
}