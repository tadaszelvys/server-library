<?php

namespace OAuth2\Client;

interface PasswordClientInterface extends ConfidentialClientInterface
{
    /**
     * @return string
     */
    public function getSecret();

    /**
     * @param string $secret
     */
    public function setSecret($secret);

    /**
     * @return string
     */
    public function getSalt();

    /**
     * @param string $salt
     */
    public function setSalt($salt);

    /**
     * @return string
     */
    public function getPlaintextSecret();

    /**
     * @param string $plaintext_secret
     */
    public function setPlaintextSecret($plaintext_secret);

    /**
     */
    public function clearCredentials();

    /**
     * @return string
     */
    public function getA1Hash();

    /**
     * @param string $ha1
     */
    public function setA1Hash($ha1);
}
