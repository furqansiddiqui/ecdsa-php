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

namespace FurqanSiddiqui\ECDSA\OpenSSL;

use FurqanSiddiqui\DataTypes\Binary;

/**
 * Class OpenSSL
 * @package FurqanSiddiqui\ECDSA\OpenSSL
 */
class OpenSSL
{
    /**
     * @param string $data
     * @param string $type
     * @param string $eol
     * @return string
     */
    public static function der2pem(string $data, string $type = "PRIVATE KEY", string $eol = "\n"): string
    {
        $type = strtoupper($type);
        $pem = sprintf("-----BEGIN %s-----", $type) . $eol;
        $pem .= chunk_split(base64_encode($data), 64, $eol);
        $pem .= sprintf("-----END %s-----", $type) . $eol;

        return $pem;
    }

    /**
     * @param string $pem
     * @param string $eol
     * @return string|null
     */
    public static function pem2der(string $pem, string $eol = "\n"): ?string
    {
        $split = preg_split('/[-]{5}[\w\s]+[-]{5}/i', $pem);
        $body = $split[1] ?? null;
        if ($body) {
            $body = implode("", explode($eol, trim($body)));
            return base64_decode($body);
        }

        return null;
    }

    /**
     * @param Binary $privateKey
     * @return array
     */
    public static function Secp256k1(Binary $privateKey): array
    {
        $key = sprintf("302e0201010420%sa00706052b8104000a", $privateKey->get()->base16(false));
        $pem = self::der2pem(hex2bin($key), "EC PRIVATE KEY");
        return openssl_pkey_get_details(openssl_pkey_get_private($pem));
    }
}