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

namespace FurqanSiddiqui\ECDSA\Vector;

use FurqanSiddiqui\BcMath\BcNumber;
use FurqanSiddiqui\ECDSA\Exception\GenerateVectorException;

/**
 * Class Coordinates
 * @package FurqanSiddiqui\ECDSA\Vector
 */
class Coordinates
{
    private const POINTS = ["x", "y", "a", "b", "d"];

    /** @var array */
    private $coords;

    /**
     * Coordinates constructor.
     */
    public function __construct()
    {
        $this->coords = [];
    }

    /**
     * @param string $point
     * @param BcNumber $value
     * @return Coordinates
     * @throws GenerateVectorException
     */
    public function set(string $point, BcNumber $value): self
    {
        $point = strtolower($point);
        if (!in_array($point, self::POINTS)) {
            throw new GenerateVectorException('Invalid vector coordinate point');
        }

        $this->coords[$point] = $value;
        return $this;
    }

    /**
     * @param string $point
     * @return BcNumber|null
     * @throws GenerateVectorException
     */
    public function get(string $point): ?BcNumber
    {
        $point = strtolower($point);
        if (!in_array($point, self::POINTS)) {
            throw new GenerateVectorException('Invalid vector coordinate point');
        }

        return $this->coords[$point] ?? null;
    }

    /**
     * @return BcNumber|null
     * @throws GenerateVectorException
     */
    public function x(): ?BcNumber
    {
        return $this->get("x");
    }

    /**
     * @return BcNumber|null
     * @throws GenerateVectorException
     */
    public function y(): ?BcNumber
    {
        return $this->get("y");
    }

    /**
     * @return array
     */
    public function array(): array
    {
        return $this->coords;
    }
}