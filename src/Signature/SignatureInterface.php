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

namespace FurqanSiddiqui\ECDSA\Signature;

use Comely\DataTypes\Buffer\Base16;

/**
 * Interface SignatureInterface
 * @package FurqanSiddiqui\ECDSA\Signature
 */
interface SignatureInterface
{
    /**
     * @return Base16
     */
    public function r(): Base16;

    /**
     * @return Base16
     */
    public function s(): Base16;
}
