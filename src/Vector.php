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

namespace FurqanSiddiqui\ECDSA;

use FurqanSiddiqui\BcMath\BcNumber;
use FurqanSiddiqui\ECDSA\Curves\EllipticCurveInterface;
use FurqanSiddiqui\ECDSA\Vector\Coordinates;

/**
 * Class Vector
 * @package FurqanSiddiqui\ECDSA
 */
class Vector
{
    /** @var EllipticCurveInterface */
    private $curve;
    /** @var Coordinates */
    private $coords;
    /** @var null|BcNumber */
    private $prime;
    /** @var null|BcNumber */
    private $order;

    /**
     * Vector constructor.
     * @param EllipticCurveInterface $curve
     * @param Coordinates|null $coords
     */
    public function __construct(EllipticCurveInterface $curve, ?Coordinates $coords = null)
    {
        $this->curve = $curve;
        $this->coords = $coords ? $coords : new Coordinates();
    }

    /**
     * @param string $prop
     * @param BcNumber $num
     * @return Vector
     */
    public function setBcNumber(string $prop, BcNumber $num): self
    {
        switch ($prop) {
            case "prime":
            case "order":
                $this->$prop = $num;
                return $this;
        }

        throw new \DomainException('Cannot set inaccessible Vector object property');
    }

    /**
     * @return EllipticCurveInterface
     */
    public function curve(): EllipticCurveInterface
    {
        return $this->curve;
    }

    /**
     * @return Coordinates
     */
    public function coords(): Coordinates
    {
        return $this->coords;
    }

    /**
     * @return BcNumber|null
     */
    public function prime(): ?BcNumber
    {
        return $this->prime;
    }

    /**
     * @return BcNumber|null
     */
    public function order(): ?BcNumber
    {
        return $this->order;
    }

    /**
     * @return BcNumber|null
     */
    public function n(): ?BcNumber
    {
        return $this->order;
    }
}