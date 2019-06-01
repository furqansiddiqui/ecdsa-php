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

namespace FurqanSiddiqui\ECDSA\ECC;

use FurqanSiddiqui\DataTypes\Base16;

/**
 * Interface EllipticCurveInterface
 * @package FurqanSiddiqui\ECDSA\ECC
 */
interface EllipticCurveInterface
{
    /**
     * @return \GMP
     */
    public function prime(): \GMP;

    /**
     * @return \GMP
     */
    public function order(): \GMP;

    /**
     * @param Base16 $privateKey
     * @return PublicKey
     */
    public function getPublicKey(Base16 $privateKey): PublicKey;

    /**
     * @param Base16 $compressed
     * @return PublicKey
     */
    public function getPublicKeyFromCompressed(Base16 $compressed): PublicKey;

    /**
     * @param Base16 $publicKey
     * @return PublicKey
     */
    public function usePublicKey(Base16 $publicKey): PublicKey;
}