<?php

namespace OAuth2\Client;

class JWTClient extends ConfidentialClient implements JWTClientInterface
{
    /**
     * @var string[]
     */
    protected $allowed_signature_algorithms = [];

    /**
     * @var array
     */
    protected $signature_public_key_set = [];

    public function __construct()
    {
        parent::__construct();
        $this->setType('jwt_client');
    }

    /**
     * @param array $key_set
     */
    public function setSignaturePublicKeySet(array $key_set)
    {
        $this->signature_public_key_set = $key_set;
    }

    /**
     * @return array
     */
    public function getSignaturePublicKeySet()
    {
        return $this->signature_public_key_set;
    }

    /**
     * @param string[] $allowed_signature_algorithms
     */
    public function setAllowedSignatureAlgorithms(array $allowed_signature_algorithms)
    {
        $this->allowed_signature_algorithms = $allowed_signature_algorithms;
    }

    /**
     * @return string[]
     */
    public function getAllowedSignatureAlgorithms()
    {
        return $this->allowed_signature_algorithms;
    }
}
