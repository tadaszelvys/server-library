<?php

namespace OAuth2\Test\Stub;

use Jose\JWKSetInterface;
use OAuth2\Client\JWTClient as BaseJWTClient;

class JWTClient extends BaseJWTClient
{
    /**
     * @var \Jose\JWKSetInterface
     */
    private $jwk_set;

    /**
     * @var string[]
     */
    private $allowed_signature_algorithms = [];

    /**
     * {@inheritdoc}
     */
    public function getType()
    {
        return 'jwt_client';
    }

    /**
     * @param \Jose\JWKSetInterface $jwk_set
     *
     * @return self
     */
    public function setPublicKeySet(JWKSetInterface $jwk_set)
    {
        $this->jwk_set = $jwk_set;

        return $this;
    }

    /**
     * {@inheritdoc}
     */
    public function getPublicKeySet()
    {
        return $this->jwk_set;
    }

    /**
     * @param string[] $allowed_signature_algorithms
     *
     * @return self
     */
    public function setAllowedSignatureAlgorithms(array $allowed_signature_algorithms)
    {
        $this->allowed_signature_algorithms = $allowed_signature_algorithms;

        return $this;
    }

    /**
     * {@inheritdoc}
     */
    public function getAllowedSignatureAlgorithms()
    {
        return $this->allowed_signature_algorithms;
    }
}
