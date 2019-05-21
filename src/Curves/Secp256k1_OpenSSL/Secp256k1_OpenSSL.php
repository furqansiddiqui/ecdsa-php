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

namespace FurqanSiddiqui\ECDSA\Curves\Secp256k1_OpenSSL;

use FurqanSiddiqui\BcMath\BcNumber;
use FurqanSiddiqui\DataTypes\Binary;
use FurqanSiddiqui\ECDSA\Curves\AbstractCurve;
use FurqanSiddiqui\ECDSA\Curves\Secp256k1\Secp256k1Constants;
use FurqanSiddiqui\ECDSA\Exception\GenerateVectorException;
use FurqanSiddiqui\ECDSA\OpenSSL\OpenSSL;
use FurqanSiddiqui\ECDSA\Vector;
use FurqanSiddiqui\ECDSA\Vector\Coordinates;

/**
 * Class Secp256k1_OpenSSL
 * @package FurqanSiddiqui\ECDSA\Curves\Secp256k1_OpenSSL
 */
class Secp256k1_OpenSSL extends AbstractCurve
{
    protected const NAME = "secp256k1";

    /**
     * @param Binary $privateKey
     * @return Vector
     * @throws GenerateVectorException
     * @throws \FurqanSiddiqui\ECDSA\Exception\ECDSA_Exception
     */
    public function vectorFromPrivateKey(Binary $privateKey): Vector
    {
        OpenSSL::CheckExtIsLoaded();
        $pKey = openssl_pkey_get_details(openssl_pkey_get_private(OpenSSL::Secp256k1_PrivateKeyPEM($privateKey)));

        $pKeyCurveOID = $pKey["ec"]["curve_oid"] ?? null;
        if ($pKeyCurveOID !== Secp256k1Constants::OID) {
            throw new GenerateVectorException('Bad curve OID from OpenSSL::Secp256k1');
        }

        $coords = new Coordinates();
        foreach (["d", "x", "y"] as $point) {
            $value = $pKey["ec"][$point] ?? null;
            if (!is_string($value) || !$value) {
                throw new GenerateVectorException(
                    sprintf('Bad/invalid vector coordinate point "%s" from OpenSSL::Secp256k1', $point)
                );
            }

            $coords->set($point, BcNumber::Decode(bin2hex($value)));
        }

        $vector = new Vector($this, $coords);
        $vector->setBcNumber("prime", new BcNumber(Secp256k1Constants::PRIME));
        $vector->setBcNumber("order", new BcNumber(Secp256k1Constants::ORDER));
        return $vector;
    }
}