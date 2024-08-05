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

use Charcoal\Buffers\AbstractByteArray;
use FurqanSiddiqui\ECDSA\Signature\Signature;

/**
 * Interface EllipticCurveInterface
 * @package FurqanSiddiqui\ECDSA\ECC
 */
interface EllipticCurveInterface
{
    /**
     * @param \Charcoal\Buffers\AbstractByteArray $privateKey
     * @return bool
     * @throws \FurqanSiddiqui\ECDSA\Exception\ECDSA_Exception
     */
    public function validatePrivateKey(#[\SensitiveParameter] AbstractByteArray $privateKey): bool;

    /**
     * @param \Charcoal\Buffers\AbstractByteArray $privateKey
     * @return \FurqanSiddiqui\ECDSA\ECC\PublicKey
     */
    public function generatePublicKey(#[\SensitiveParameter] AbstractByteArray $privateKey): PublicKey;

    /**
     * @param \Charcoal\Buffers\AbstractByteArray $privateKey
     * @param \Charcoal\Buffers\AbstractByteArray $msgHash
     * @param \Charcoal\Buffers\AbstractByteArray|null $randomK
     * @return \FurqanSiddiqui\ECDSA\Signature\Signature
     */
    public function sign(#[\SensitiveParameter] AbstractByteArray $privateKey, AbstractByteArray $msgHash, ?AbstractByteArray $randomK = null): Signature;

    /**
     * @param \FurqanSiddiqui\ECDSA\ECC\PublicKey $publicKey
     * @param \FurqanSiddiqui\ECDSA\Signature\Signature $signature
     * @param \Charcoal\Buffers\AbstractByteArray $msgHash
     * @return bool
     */
    public function verify(PublicKey $publicKey, Signature $signature, AbstractByteArray $msgHash): bool;

    /**
     * @param \FurqanSiddiqui\ECDSA\Signature\Signature $signature
     * @param \Charcoal\Buffers\AbstractByteArray $msgHash
     * @param int|null $recId
     * @return \FurqanSiddiqui\ECDSA\ECC\PublicKey
     */
    public function recoverPublicKeyFromSignature(Signature $signature, AbstractByteArray $msgHash, ?int $recId = null): PublicKey;
}
