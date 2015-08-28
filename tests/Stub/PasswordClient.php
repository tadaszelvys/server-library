<?php

namespace OAuth2\Test\Stub;

use OAuth2\Client\PasswordClient as BasePasswordClient;

class PasswordClient extends BasePasswordClient
{
    /**
     * @var string
     */
    private $secret;

    /**
     * {@inheritdoc}
     */
    public function getSecret()
    {
        return $this->secret;
    }

    /**
     * @param string $secret
     *
     * @return self
     */
    public function setSecret($secret)
    {
        $this->secret = $secret;

        return $this;
    }

    /**
     * {@inheritdoc}
     */
    public function getType()
    {
        return 'password_client';
    }
}
