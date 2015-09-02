<?php

namespace OAuth2\Client;

class PasswordClient extends ConfidentialClient implements PasswordClientInterface
{
    /**
     * @var string
     */
    private $secret;

    /**
     * @var string
     */
    private $salt;

    /**
     * @var string
     */
    private $plaintext_secret;

    public function __construct()
    {
        parent::__construct();
        $this->setSalt(base_convert(sha1(uniqid(mt_rand(), true)), 16, 36));
        $this->setType('password_client');
    }

    public function getSecret()
    {
        return $this->secret;
    }

    public function setSecret($secret)
    {
        $this->secret = $secret;

        return $this;
    }

    public function getSalt()
    {
        return $this->salt;
    }

    public function setSalt($salt)
    {
        $this->salt = $salt;

        return $this;
    }

    public function getPlaintextSecret()
    {
        return $this->plaintext_secret;
    }

    public function setPlaintextSecret($plaintext_secret)
    {
        $this->plaintext_secret = $plaintext_secret;

        return $this;
    }

    public function clearCredentials()
    {
        $this->plaintext_secret = null;

        return $this;
    }
}