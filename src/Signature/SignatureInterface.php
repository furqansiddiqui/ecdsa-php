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

use Charcoal\Buffers\AbstractByteArray;

/**
 * Interface SignatureInterface
 * @package FurqanSiddiqui\ECDSA\Signature
 */
interface SignatureInterface
{
    /**
     * @param \Charcoal\Buffers\AbstractByteArray $signature
     * @return static
     */
    public static function fromDER(AbstractByteArray $signature): static;

    /**
     * @return \Charcoal\Buffers\AbstractByteArray
     */
    public function getDER(): AbstractByteArray;

    /**
     * @param \Charcoal\Buffers\AbstractByteArray $signature
     * @return static
     */
    public static function fromCompact(AbstractByteArray $signature): static;

    /**
     * @return \Charcoal\Buffers\AbstractByteArray
     */
    public function getCompact(): AbstractByteArray;
}
