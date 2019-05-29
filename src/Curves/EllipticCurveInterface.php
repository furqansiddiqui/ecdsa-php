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

namespace FurqanSiddiqui\ECDSA\Curves;

use FurqanSiddiqui\DataTypes\Binary;
use FurqanSiddiqui\ECDSA\PublicKey;
use FurqanSiddiqui\ECDSA\Signature;
use FurqanSiddiqui\ECDSA\Vector;

/**
 * Interface EllipticCurveInterface
 * @package FurqanSiddiqui\ECDSA\Curves
 */
interface EllipticCurveInterface
{
    /**
     * @return static
     */
    public static function getInstance();

    /**
     * @return string|null
     */
    public function name(): ?string;

    /**
     * @param Binary $privateKey
     * @return Vector
     */
    public function vectorFromPrivateKey(Binary $privateKey): Vector;

    /**
     * @param Binary $privateKey
     * @return PublicKey
     */
    public function publicKeyFromPrivateKey(Binary $privateKey): PublicKey;

    /**
     * @param Binary $privateKey
     * @param Binary $msgHash
     * @param Binary|null $randomK
     * @return Signature
     */
    public function sign(Binary $privateKey, Binary $msgHash, ?Binary $randomK = null): Signature;
}