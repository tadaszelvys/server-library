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
     *
     * @return self
     */
    public function setSecret($secret);

    /**
     * @return string
     */
    public function getSalt();

    /**
     * @param string $salt
     *
     * @return self
     */
    public function setSalt($salt);

    /**
     * @return string
     */
    public function getPlaintextSecret();

    /**
     * @param string $plaintext_secret
     *
     * @return self
     */
    public function setPlaintextSecret($plaintext_secret);

    /**
     * @return self
     */
    public function clearCredentials();
}
