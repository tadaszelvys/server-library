<?php

namespace OAuth2\Util;

use Jose\JSONSerializationModes;
use Jose\JWKManagerInterface;
use Jose\SignerInterface;
use SpomkyLabs\Jose\SignatureInstruction;

class JWTSigner
{
    /**
     * @var \Jose\SignerInterface
     */
    protected $jwt_signer;

    /**
     * @var \Jose\JWKManagerInterface
     */
    protected $key_manager;

    /**
     * @var \Jose\JWKInterface
     */
    protected $signature_key;

    /**
     * @return \Jose\JWKManagerInterface
     */
    public function getKeyManager()
    {
        return $this->key_manager;
    }

    /**
     * @param  $key_manager
     *
     * @return self
     */
    public function setKeyManager(JWKManagerInterface $key_manager)
    {
        $this->key_manager = $key_manager;

        return $this;
    }

    /**
     * @return \Jose\SignerInterface
     */
    public function getJWTSigner()
    {
        return $this->jwt_signer;
    }

    /**
     * @param \Jose\SignerInterface $jwt_signer
     *
     * @return self
     */
    public function setJWTSigner(SignerInterface $jwt_signer)
    {
        $this->jwt_signer = $jwt_signer;

        return $this;
    }

    /**
     * @return \Jose\JWKInterface
     */
    public function getSignatureKey()
    {
        return $this->signature_key;
    }

    /**
     * @param array $signature_key
     *
     * @return self
     */
    public function setSignatureKey(array $signature_key)
    {
        $this->signature_key = $this->getKeyManager()->createJWK($signature_key);

        return $this;
    }

    /**
     * @param array $claims
     * @param array $protected_headers
     *
     * @return string
     */
    public function sign(array $claims, array $protected_headers)
    {
        $instruction = new SignatureInstruction();
        $instruction->setKey($this->getSignatureKey())
            ->setProtectedHeader($protected_headers);

        $result = $this->getJWTSigner()->sign($claims, [$instruction], JSONSerializationModes::JSON_COMPACT_SERIALIZATION);
        if (!is_string($result)) {
            throw new \RuntimeException('Unable to sign claims.');
        }

        return $result;
    }
}
