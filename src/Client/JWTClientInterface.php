<?php

namespace OAuth2\Client;

interface JWTClientInterface extends ConfidentialClientInterface
{
    /**
     * @param array $key_set
     *
     * @return self
     */
    public function setSignaturePublicKeySet(array $key_set);

    /**
     * @return array
     */
    public function getSignaturePublicKeySet();

    /**
     * @param string[] $allowed_signature_algorithms
     *
     * @return self
     */
    public function setAllowedSignatureAlgorithms(array $allowed_signature_algorithms);

    /**
     * @return string[]
     */
    public function getAllowedSignatureAlgorithms();
}
