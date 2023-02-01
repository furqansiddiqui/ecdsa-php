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

use Comely\Buffer\AbstractByteArray;
use FurqanSiddiqui\ECDSA\Signature\Signature;

/**
 * Interface EllipticCurveInterface
 * @package FurqanSiddiqui\ECDSA\ECC
 */
interface EllipticCurveInterface
{
    /**
     * @param \Comely\Buffer\AbstractByteArray $privateKey
     * @return bool
     */
    public function validatePrivateKey(AbstractByteArray $privateKey): bool;

    /**
     * @param \Comely\Buffer\AbstractByteArray $privateKey
     * @return \FurqanSiddiqui\ECDSA\ECC\PublicKey
     */
    public function generatePublicKey(AbstractByteArray $privateKey): PublicKey;

    /**
     * @param \Comely\Buffer\AbstractByteArray $compressed
     * @return \FurqanSiddiqui\ECDSA\ECC\PublicKey
     */
    public function getPublicKeyFromCompressed(AbstractByteArray $compressed): PublicKey;

    /**
     * @param \Comely\Buffer\AbstractByteArray $privateKey
     * @param \Comely\Buffer\AbstractByteArray $msgHash
     * @param \Comely\Buffer\AbstractByteArray|null $randomK
     * @return \FurqanSiddiqui\ECDSA\Signature\Signature
     */
    public function sign(AbstractByteArray $privateKey, AbstractByteArray $msgHash, ?AbstractByteArray $randomK = null): Signature;

    /**
     * @param \FurqanSiddiqui\ECDSA\ECC\PublicKey $publicKey
     * @param \FurqanSiddiqui\ECDSA\Signature\Signature $signature
     * @param \Comely\Buffer\AbstractByteArray $msgHash
     * @return bool
     */
    public function verify(PublicKey $publicKey, Signature $signature, AbstractByteArray $msgHash): bool;

    /**
     * @param \FurqanSiddiqui\ECDSA\Signature\Signature $signature
     * @param \Comely\Buffer\AbstractByteArray $msgHash
     * @param int|null $recId
     * @return \FurqanSiddiqui\ECDSA\ECC\PublicKey
     */
    public function recoverPublicKeyFromSignature(Signature $signature, AbstractByteArray $msgHash, ?int $recId = null): PublicKey;
}
