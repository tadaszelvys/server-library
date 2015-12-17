<?php

/*
 * The MIT License (MIT)
 *
 * Copyright (c) 2014-2015 Spomky-Labs
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file for details.
 */

namespace OAuth2\Client;

class PasswordClient extends ConfidentialClient implements PasswordClientInterface
{
    /**
     * @var string
     */
    protected $secret;

    /**
     * @var string
     */
    protected $salt;

    /**
     * @var string
     */
    protected $ha1;

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

    /**
     * {@inheritdoc}
     */
    public function getSecret()
    {
        return $this->secret;
    }

    /**
     * {@inheritdoc}
     */
    public function setSecret($secret)
    {
        $this->secret = $secret;
    }

    /**
     * {@inheritdoc}
     */
    public function getSalt()
    {
        return $this->salt;
    }

    /**
     * {@inheritdoc}
     */
    public function setSalt($salt)
    {
        $this->salt = $salt;
    }

    /**
     * {@inheritdoc}
     */
    public function getPlaintextSecret()
    {
        return $this->plaintext_secret;
    }

    /**
     * {@inheritdoc}
     */
    public function setPlaintextSecret($plaintext_secret)
    {
        $this->plaintext_secret = $plaintext_secret;
    }

    /**
     * {@inheritdoc}
     */
    public function clearCredentials()
    {
        $this->plaintext_secret = null;
    }

    /**
     * {@inheritdoc}
     */
    public function getA1Hash()
    {
        return $this->ha1;
    }

    /**
     * {@inheritdoc}
     */
    public function setA1Hash($ha1)
    {
        $this->ha1 = $ha1;
    }
}
