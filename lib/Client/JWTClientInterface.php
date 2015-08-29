<?php

namespace OAuth2\Client;

interface JWTClientInterface extends ConfidentialClientInterface
{
    /**
     * @return \Jose\JWKSet
     */
    public function getPublicKeySet();

    /**
     * @return string[]
     */
    public function getAllowedSignatureAlgorithms();
}
