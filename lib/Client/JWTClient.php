<?php

namespace OAuth2\Client;

use Jose\JWKSetInterface;

class JWTClient extends ConfidentialClient implements JWTClientInterface
{
    /**
     * @var string[]
     */
    private $allowed_signature_algorithms = [];

    /**
     * @var string[]
     */
    private $key_set = [];

    public function __construct()
    {
        parent::__construct();
        $this->setType('jwt_client');
    }

    /**
     * @param \Jose\JWKSetInterface $key_set
     *
     * @return self
     */
    public function setPublicKeySet(JWKSetInterface $key_set)
    {
        $this->key_set = $key_set;

        return $this;
    }

    public function getPublicKeySet()
    {
        return $this->key_set;
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
     * @return string[]
     */
    public function getAllowedSignatureAlgorithms()
    {
        return $this->allowed_signature_algorithms;
    }
}
