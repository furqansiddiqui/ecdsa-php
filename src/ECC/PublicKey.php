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

use Comely\DataTypes\Buffer\Base16;

/**
 * Class PublicKey
 * @package FurqanSiddiqui\ECDSA
 */
class PublicKey
{
    /** @var Base16 */
    private Base16 $x;
    /** @var Base16 */
    private Base16 $y;

    /**
     * PublicKey constructor.
     * @param Base16 $x
     * @param Base16 $y
     */
    public function __construct(Base16 $x, Base16 $y)
    {
        $this->x = $x->readOnly(true);
        $this->y = $y->readOnly(true);
    }

    /**
     * @return Base16
     */
    public function x(): Base16
    {
        return $this->x;
    }

    /**
     * @return Base16
     */
    public function y(): Base16
    {
        return $this->y;
    }

    /**
     * @return Base16
     */
    public function getUnCompressed(): Base16
    {
        return (new Base16("04" . $this->x->hexits() . $this->y->hexits()))
            ->readOnly(true);
    }

    /**
     * @return Base16
     */
    public function getCompressed(): Base16
    {
        $prefix = gmp_strval(gmp_mod(gmp_init($this->y->hexits(), 16), gmp_init(2, 10))) === "0" ? "02" : "03";
        return (new Base16($prefix . $this->x->hexits()));
    }
}
