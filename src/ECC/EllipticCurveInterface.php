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
use FurqanSiddiqui\ECDSA\Signature\Signature;

/**
 * Interface EllipticCurveInterface
 * @package FurqanSiddiqui\ECDSA\ECC
 */
interface EllipticCurveInterface
{
    /**
     * @return \GMP
     */
    public function prime(): \GMP;

    /**
     * @return \GMP
     */
    public function order(): \GMP;

    /**
     * @param Base16 $privateKey
     * @return PublicKey
     */
    public function getPublicKey(Base16 $privateKey): PublicKey;

    /**
     * @param Base16 $compressed
     * @return PublicKey
     */
    public function getPublicKeyFromCompressed(Base16 $compressed): PublicKey;

    /**
     * @param Base16 $publicKey
     * @return PublicKey
     */
    public function usePublicKey(Base16 $publicKey): PublicKey;

    /**
     * @param Signature $signature
     * @param Base16 $msgHash
     * @param int $flag
     * @return PublicKey
     */
    public function recoverPublicKeyFromSignature(Signature $signature, Base16 $msgHash, int $flag): PublicKey;

    /**
     * @param PublicKey $publicKey
     * @param Signature $signature
     * @param Base16 $msgHash
     * @param bool $compressed
     * @return int
     */
    public function findRecoveryId(PublicKey $publicKey, Signature $signature, Base16 $msgHash, bool $compressed): int;

    /**
     * @param PublicKey $publicKey
     * @param Signature $signature
     * @param Base16 $msgHash
     * @return bool
     */
    public function verify(PublicKey $publicKey, Signature $signature, Base16 $msgHash): bool;

    /**
     * @param Base16 $privateKey
     * @param Base16 $msgHash
     * @param Base16|null $randomK
     * @return Signature
     */
    public function sign(Base16 $privateKey, Base16 $msgHash, ?Base16 $randomK = null): Signature;
}
