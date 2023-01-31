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

use Comely\Buffer\AbstractByteArray;

/**
 * Interface SignatureInterface
 * @package FurqanSiddiqui\ECDSA\Signature
 */
interface SignatureInterface
{
    /**
     * @param string|\Comely\Buffer\AbstractByteArray $signature
     * @return static
     */
    public static function fromDER(string|AbstractByteArray $signature): static;

    /**
     * @return \Comely\Buffer\AbstractByteArray
     */
    public function getDER(): AbstractByteArray;
}
