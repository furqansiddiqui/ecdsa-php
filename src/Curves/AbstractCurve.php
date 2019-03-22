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
use FurqanSiddiqui\ECDSA\Vector;

/**
 * Class AbstractCurve
 * @package FurqanSiddiqui\ECDSA\Curves
 */
abstract class AbstractCurve
{
    protected const NAME = null;

    /**
     * @return string|null
     */
    final public function name(): ?string
    {
        return static::NAME;
    }

    /**
     * @param Binary $privateKey
     * @return Vector
     */
    abstract public function vectorFromPrivateKey(Binary $privateKey): Vector;
}