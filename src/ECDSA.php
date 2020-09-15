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

declare(strict_types=1);

namespace FurqanSiddiqui\ECDSA;

use FurqanSiddiqui\ECDSA\Curves\Secp256k1;

/**
 * Class ECDSA
 * @package FurqanSiddiqui\ECDSA
 */
class ECDSA
{
    /**
     * @return Secp256k1
     */
    public static function Secp256k1(): Secp256k1
    {
        return Secp256k1::getInstance();
    }
}
