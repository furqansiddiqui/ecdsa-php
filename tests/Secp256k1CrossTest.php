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

/**
 * Class Secp256K1CrossTest
 */
class Secp256K1CrossTest extends \PHPUnit\Framework\TestCase
{
    private const RPC_HOST = "127.0.0.1";
    private const RPC_PORT = 27270;
    private const KEYPAIR_TEST_ITERATIONS = 100;
    private const SIGNATURES_TEST_ITERATIONS = 100;

    private ?\FurqanSiddiqui\ECDSA\Curves\Secp256k1_RPC $rpc = null;

    /**
     * @return void
     * @throws \FurqanSiddiqui\ECDSA\Exception\ECDSA_Exception
     * @throws \FurqanSiddiqui\ECDSA\Exception\ECDSA_RPC_Exception
     */
    public function testKeyPairs(): void
    {
        $eccGmp = \FurqanSiddiqui\ECDSA\ECDSA::Secp256k1_GMP();
        $eccRpc = $this->getRpcInstance();
        $iterations = static::KEYPAIR_TEST_ITERATIONS;

        // Generate N different private key samples using PRNG
        $secrets = [];
        for ($i = 0; $i < $iterations; $i++) {
            $secrets[] = \Charcoal\Buffers\Frames\Bytes32::fromRandomBytes();
        }

        // Generate PublicKey instances using Secp256k1_GMP
        $gmpStart = microtime(true);
        $gmpPublicKeys = [];
        foreach ($secrets as $secret) {
            $gmpPublicKeys[] = $eccGmp->generatePublicKey($secret);
        }

        $gmpFinish = microtime(true);
        $this->assertTrue(true, sprintf("Secp256k1_GMP time for %d keys: %s", $iterations, number_format(($gmpFinish - $gmpStart), 4, ".", "")));

        // Generate PublicKey instances using Secp256k1_RPC (bitcoind's native C lib)
        $rpcStart = microtime(true);
        $rpcPublicKeys = [];
        foreach ($secrets as $secret) {
            $rpcPublicKeys[] = $eccRpc->generatePublicKey($secret);
        }

        $rpcFinish = microtime(true);
        $this->assertTrue(true, sprintf("Secp256k1_RPC time for %d keys: %s", $iterations, number_format(($rpcFinish - $rpcStart), 4, ".", "")));

        // Compare Private Keys
        foreach ($secrets as $i => $secret) {
            unset($gmpPublicKey, $rpcPublicKey);

            $gmpPublicKey = $gmpPublicKeys[$i];
            $rpcPublicKey = $rpcPublicKeys[$i];

            $this->assertNotEquals(spl_object_id($gmpPublicKey), spl_object_id($rpcPublicKey));

            $this->assertEquals(
                $gmpPublicKey->getCompressed()->raw(),
                $rpcPublicKey->getCompressed()->raw(),
                "[0x" . $secret->toBase16() . "] Compressed"
            );

            $this->assertEquals(
                $gmpPublicKey->getUnCompressed()->raw(),
                $rpcPublicKey->getUnCompressed()->raw(),
                "[0x" . $secret->toBase16() . "] Uncompressed"
            );
        }
    }

    /**
     * @return void
     * @throws \FurqanSiddiqui\ECDSA\Exception\ECDSA_Exception
     * @throws \FurqanSiddiqui\ECDSA\Exception\ECDSA_RPC_Exception
     * @throws \FurqanSiddiqui\ECDSA\Exception\KeyPairException
     * @throws \FurqanSiddiqui\ECDSA\Exception\SignatureException
     * @throws \Random\RandomException
     */
    public function testSignatures(): void
    {
        $eccGmp = \FurqanSiddiqui\ECDSA\ECDSA::Secp256k1_GMP();
        $eccRpc = $this->getRpcInstance();

        // Generate a random message for test
        $msgHash1 = new \Charcoal\Buffers\Frames\Bytes32(random_bytes(32));
        $msgHash2 = new \Charcoal\Buffers\Frames\Bytes32(random_bytes(32));
        $this->assertNotEquals($msgHash1->raw(), $msgHash2->raw(), "Message hash 1 & 2 same");
        $msgHash3 = new \Charcoal\Buffers\Frames\Bytes32(random_bytes(32));
        $this->assertNotEquals($msgHash2->raw(), $msgHash3->raw(), "Message hash 2 & 3 same");

        for ($i = 0; $i < static::SIGNATURES_TEST_ITERATIONS; $i++) {
            unset($privateKey, $keyPairGmp, $keyPairRpc);
            unset($signedGmp1, $signedGmp2, $signedRpc1, $signedRpc2);

            // Generate a secure 256bit entropy
            $privateKey = new \Charcoal\Buffers\Frames\Bytes32(random_bytes(32));

            // Create KeyPair instance from both GMP and RPC curve variants
            $keyPairGmp = new \FurqanSiddiqui\ECDSA\KeyPair($eccGmp, $privateKey);
            $keyPairRpc = new \FurqanSiddiqui\ECDSA\KeyPair($eccRpc, $privateKey);

            // Bonus check, public keys must obviously match
            $this->assertEquals(
                $keyPairGmp->public()->getUnCompressed()->toBase16(),
                $keyPairRpc->public()->getUnCompressed()->toBase16(),
                "[0x" . $privateKey->toBase16() . "] Public Keys"
            );

            // Sign with RPC keypair
            $signedRpc1 = $keyPairRpc->signRecoverable($msgHash1);
            $signedGmp1 = $keyPairGmp->signRecoverable($msgHash1);
            $this->assertEquals($signedGmp1->getDER()->toBase16(), $signedRpc1->getDER()->toBase16(), "Signatures match");

            $signedRpc2 = $keyPairRpc->signRecoverable($msgHash2);
            $this->assertNotEquals($signedRpc1->getDER()->raw(), $signedRpc2->getDER()->raw(), "Same signature for message 1 & 2");
            $this->assertTrue($keyPairGmp->verify($signedRpc2, $msgHash2), "GMP verifies RPC signed message 2");

            $signedGmp2 = $keyPairRpc->signRecoverable($msgHash3);
            $this->assertNotEquals($signedGmp1->getDER()->raw(), $signedGmp2->getDER()->raw(), "Same signature for message 1 & 3");
            $this->assertTrue($keyPairRpc->verify($signedGmp2, $msgHash3), "GMP verifies RPC signed message 3");
        }
    }

    /**
     * @return \FurqanSiddiqui\ECDSA\Curves\Secp256k1_RPC
     * @throws \FurqanSiddiqui\ECDSA\Exception\ECDSA_Exception
     * @throws \FurqanSiddiqui\ECDSA\Exception\ECDSA_RPC_Exception
     */
    private function getRpcInstance(): \FurqanSiddiqui\ECDSA\Curves\Secp256k1_RPC
    {
        if ($this->rpc) {
            return $this->rpc;
        }

        $eccRpc = new \FurqanSiddiqui\ECDSA\Curves\Secp256k1_RPC(static::RPC_HOST, static::RPC_PORT);
        $eccRpc->testConnection();
        return $this->rpc = $eccRpc;
    }
}

