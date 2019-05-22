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