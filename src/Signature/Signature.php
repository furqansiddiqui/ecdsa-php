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
use FurqanSiddiqui\ECDSA\ECC\Point;

/**
 * Class Signature
 * @package FurqanSiddiqui\ECDSA\Signature
 */
class Signature
{
    /** @var Base16 */
    private Base16 $r;
    /** @var Base16 */
    private Base16 $s;
    /** @var Point */
    private Point $curvePointR;

    /**
     * Signature constructor.
     * @param Base16 $r
     * @param Base16 $s
     * @param Point $curvePointR
     */
    public function __construct(Base16 $r, Base16 $s, Point $curvePointR)
    {
        $this->r = $r;
        $this->s = $s;
        $this->curvePointR = $curvePointR;
    }

    /**
     * @return Base16
     */
    public function r(): Base16
    {
        return $this->r;
    }

    /**
     * @return Base16
     */
    public function s(): Base16
    {
        return $this->s;
    }

    /**
     * @return Base16
     */
    public function getDER(): Base16
    {
        $der = new Base16();

        // Prepare R
        $r = $this->r()->copy();
        if (substr($r->binary()->bitwise()->value(), 0, 1) === "1") {
            $r->prepend("00");
        }

        $der->append("02"); // Append R
        $der->append(dechex($r->binary()->size()->bytes()));
        $der->append($r->hexits());

        // Prepare S
        $s = $this->s()->copy();
        if (substr($s->binary()->bitwise()->value(), 0, 1) === "1") {
            $s->prepend("00");
        }

        $der->append("02"); // Append S
        $der->append(dechex($s->binary()->size()->bytes()));
        $der->append($s->hexits());

        // DER prefix
        $der->prepend(dechex($der->binary()->size()->bytes()));
        $der->prepend("30");

        return $der->readOnly(true);
    }
}