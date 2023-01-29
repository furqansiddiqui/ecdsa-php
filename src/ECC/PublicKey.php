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

namespace FurqanSiddiqui\ECDSA\ECC;

use Comely\Buffer\Buffer;

/**
 * Class PublicKey
 * @package FurqanSiddiqui\ECDSA
 */
class PublicKey
{
    /**
     * @param string $x as base16/hex
     * @param string $y as base16/hex
     */
    public function __construct(
        public readonly string $x,
        public readonly string $y
    )
    {
    }

    /**
     * @return \Comely\Buffer\Buffer
     */
    public function getUnCompressed(): Buffer
    {
        return (new Buffer(hex2bin("04" . $this->x . $this->y)))->readOnly();
    }

    /**
     * @return \Comely\Buffer\Buffer
     */
    public function getCompressed(): Buffer
    {
        $prefix = gmp_strval(gmp_mod(gmp_init($this->y, 16), gmp_init(2, 10))) === "0" ? "02" : "03";
        return (new Buffer(hex2bin($prefix . $this->x)))->readOnly();
    }
}
