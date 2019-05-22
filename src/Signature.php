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
 * Class Signature
 * @package FurqanSiddiqui\ECDSA
 */
class Signature
{
    /** @var Binary */
    private $r;
    /** @var Binary */
    private $s;

    /**
     * Signature constructor.
     * @param Binary $r
     * @param Binary $s
     */
    public function __construct(Binary $r, Binary $s)
    {
        $this->r = $r;
        $this->s = $s;
    }

    /**
     * @return Binary
     */
    public function r(): Binary
    {
        return $this->r;
    }

    /**
     * @return Binary
     */
    public function s(): Binary
    {
        return $this->s;
    }

    /**
     * @return Binary
     */
    public function getCompact(): Binary
    {
        return new Binary(sprintf("%s%s%s", chr($this->r->size()->bytes()), $this->r->raw(), $this->s->raw()));
    }
}