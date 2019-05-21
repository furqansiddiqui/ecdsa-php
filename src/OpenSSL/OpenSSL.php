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

use FurqanSiddiqui\DataTypes\Base16;
use FurqanSiddiqui\DataTypes\Binary;
use FurqanSiddiqui\ECDSA\Exception\ECDSA_Exception;

/**
 * Class OpenSSL
 * @package FurqanSiddiqui\ECDSA\OpenSSL
 */
class OpenSSL
{
    /**
     * @throws ECDSA_Exception
     */
    public static function CheckExtIsLoaded(): void
    {
        if (!extension_loaded("openssl")) {
            throw new ECDSA_Exception('OpenSSL extension is required for ECDSA');
        }
    }

    /**
     * @param Binary $privateKey
     * @return PEM_Certificate
     */
    public static function Secp256k1_PrivateKeyPEM(Binary $privateKey): PEM_Certificate
    {
        $secp256k1_curveKey = sprintf("302e0201010420%sa00706052b8104000a", $privateKey->get()->base16(false));
        return PEM_Certificate::fromDER(new Base16($secp256k1_curveKey), "EC PRIVATE KEY");
    }
}