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

namespace FurqanSiddiqui\ECDSA\Exception;

/**
 * Class ECDSA_RPC_Exception
 * @package FurqanSiddiqui\ECDSA\Exception
 */
class ECDSA_RPC_Exception extends \Exception
{
    /** @var \CurlHandle|null */
    public ?\CurlHandle $curlHandle = null;

    /**
     * @param \CurlHandle $ch
     * @return static
     */
    public static function CurlError(\CurlHandle $ch): static
    {
        $ex = new static(curl_error($ch));
        $ex->curlHandle = $ch;
        return $ex;
    }
}
