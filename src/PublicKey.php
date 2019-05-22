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

use FurqanSiddiqui\BcMath\BcBaseConvert;
use FurqanSiddiqui\DataTypes\Base16;
use FurqanSiddiqui\DataTypes\Binary;

/**
 * Class PublicKey
 * @package FurqanSiddiqui\ECDSA
 */
class PublicKey
{
    /** @var Binary */
    private $publicKey;
    /** @var Binary */
    private $compressed;

    /**
     * @param Vector $vector
     * @return PublicKey
     * @throws Exception\GenerateVectorException
     */
    public static function PublicKeyFromVector(Vector $vector): self
    {
        $coords = $vector->coords();
        if (!$coords->x()) {
            throw new \UnexpectedValueException('ECDSA generated vector is missing "x" point');
        } elseif (!$coords->y()) {
            throw new \UnexpectedValueException('ECDSA generated vector is missing "y" point');
        }

        $base16x = $coords->x()->encode();
        $base16y = $coords->y()->encode();
        $bitwise = BcBaseConvert::BaseConvert($base16y->hexits(false), 16, 2);
        $sign = substr($bitwise, -1) === "0" ? "02" : "03";
        $publicKey = Base16::Concat($base16x, $base16y)->readOnly(true);
        $compressedPublicKey = $base16y->clone()->prepend($sign);
        return new self($publicKey->binary(), $compressedPublicKey->binary());
    }

    /**
     * PublicKey constructor.
     * @param Binary $publicKey
     * @param Binary $compressedPublicKey
     */
    public function __construct(Binary $publicKey, Binary $compressedPublicKey)
    {
        $this->publicKey = $publicKey;
        $this->compressed = $compressedPublicKey;
    }

    /**
     * @return Binary
     */
    public function getPublicKey(): Binary
    {
        return $this->publicKey;
    }

    /**
     * @return Binary
     */
    public function getCompressed(): Binary
    {
        return $this->compressed;
    }
}