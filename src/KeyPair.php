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

namespace FurqanSiddiqui\ECDSA;

use Comely\Buffer\AbstractByteArray;
use FurqanSiddiqui\ECDSA\ECC\EllipticCurveInterface;
use FurqanSiddiqui\ECDSA\ECC\PublicKey;
use FurqanSiddiqui\ECDSA\Exception\SignatureException;
use FurqanSiddiqui\ECDSA\Signature\Signature;

/**
 * Class Keypair
 * @package FurqanSiddiqui\ECDSA
 */
class KeyPair
{

    /** @var \FurqanSiddiqui\ECDSA\ECC\PublicKey|null */
    private ?PublicKey $public = null;

    /**
     * @param \FurqanSiddiqui\ECDSA\ECC\EllipticCurveInterface $ecc
     * @param \Comely\Buffer\AbstractByteArray $private
     */
    public function __construct(
        public readonly EllipticCurveInterface $ecc,
        public readonly AbstractByteArray      $private)
    {
    }

    /**
     * Returns PublicKey instance, generates one if it does not already exist
     * @return \FurqanSiddiqui\ECDSA\ECC\PublicKey
     */
    public function public(): PublicKey
    {
        if (!$this->public) {
            $this->public = $this->ecc->generatePublicKey($this->private);
        }

        return $this->public;
    }

    /**
     * @param \Comely\Buffer\AbstractByteArray $msgHash
     * @param \Comely\Buffer\AbstractByteArray|null $nonceK
     * @return \FurqanSiddiqui\ECDSA\Signature\Signature
     */
    public function sign(AbstractByteArray $msgHash, ?AbstractByteArray $nonceK = null): Signature
    {
        return $this->ecc->sign($this->private, $msgHash, $nonceK);
    }

    /**
     * @param \Comely\Buffer\AbstractByteArray $msgHash
     * @param \Comely\Buffer\AbstractByteArray|null $nonceK
     * @return \FurqanSiddiqui\ECDSA\Signature\Signature
     * @throws \FurqanSiddiqui\ECDSA\Exception\SignatureException
     */
    public function signRecoverable(AbstractByteArray $msgHash, ?AbstractByteArray $nonceK = null): Signature
    {
        $signature = $this->ecc->sign($this->private, $msgHash, $nonceK);
        if ($signature->recoveryId > -1) {
            return $signature;
        }

        return new Signature($signature->r, $signature->s, $this->findRecoveryId($signature, $msgHash));
    }

    /**
     * @param \FurqanSiddiqui\ECDSA\Signature\Signature $sig
     * @param \Comely\Buffer\AbstractByteArray $msgHash
     * @return int
     * @throws \FurqanSiddiqui\ECDSA\Exception\SignatureException
     */
    public function findRecoveryId(Signature $sig, AbstractByteArray $msgHash): int
    {
        for ($i = 0; $i < 4; $i++) {
            try {
                $recovered = $this->ecc->recoverPublicKeyFromSignature($sig, $msgHash, $i);
                if ($this->public()->compare($recovered) === 0) {
                    return $i;
                }
            } catch (\Exception) {
            }
        }

        throw new SignatureException('Could not find valid recovery Id for signature');
    }

    /**
     * @param \FurqanSiddiqui\ECDSA\Signature\Signature $sig
     * @param \Comely\Buffer\AbstractByteArray $msgHash
     * @return bool
     */
    public function verify(Signature $sig, AbstractByteArray $msgHash): bool
    {
        return $this->ecc->verify($this->public(), $sig, $msgHash);
    }

    /**
     * @param \FurqanSiddiqui\ECDSA\Signature\Signature $sig
     * @param \Comely\Buffer\AbstractByteArray $msgHash
     * @param int|null $recId
     * @return bool
     * @throws \FurqanSiddiqui\ECDSA\Exception\SignatureException
     */
    public function verifyPublicKey(Signature $sig, AbstractByteArray $msgHash, ?int $recId = null): bool
    {
        $recId = is_int($recId) && $recId >= 0 ? $recId : $sig->recoveryId;
        if ($recId < 0) {
            throw new SignatureException('Signature does not have a recovery Id');
        }

        $recovered = $this->ecc->recoverPublicKeyFromSignature($sig, $msgHash, $recId);
        return $this->public()->compare($recovered) === 0;
    }
}
