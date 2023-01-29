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
use Comely\Buffer\Buffer;
use FurqanSiddiqui\ECDSA\ECC\Point;

/**
 * Class Signature
 * @package FurqanSiddiqui\ECDSA\Signature
 */
class Signature implements SignatureInterface
{
    /**
     * @param \Comely\Buffer\AbstractByteArray $r
     * @param \Comely\Buffer\AbstractByteArray $s
     * @param \FurqanSiddiqui\ECDSA\ECC\Point $curvePointR
     * @param \Comely\Buffer\AbstractByteArray $k
     */
    public function __construct(
        public readonly AbstractByteArray $r,
        public readonly AbstractByteArray $s,
        public readonly Point             $curvePointR,
        public readonly AbstractByteArray $k)
    {
    }

    /**
     * @return \Comely\Buffer\AbstractByteArray
     */
    public function getDER(): AbstractByteArray
    {
        $der = new Buffer();

        // Prepare R
        $r = new Buffer($this->r->raw());
        if (str_starts_with(gmp_strval(gmp_init($r->toBase16(false), 16), 2), "1")) {
            $r->prepend("\x00");
        }

        $der->append("\x02");
        $der->append(decbin($r->len()));
        $der->append($r);

        // Prepare S
        $s = new Buffer($this->s->raw());
        if (str_starts_with(gmp_strval(gmp_init($s->toBase16(false), 16), 2), "1")) {
            $s->prepend("\x00");
        }

        $der->append("\x02");
        $der->append(decbin($s->len()));
        $der->append($s);

        // DER prefix
        $der->prepend(decbin($der->len()));
        $der->prepend("\x30");
        return $der->readOnly();
    }
}
