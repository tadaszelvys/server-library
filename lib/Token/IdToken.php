<?php

namespace OAuth2\Token;

class IdToken extends Token implements IdTokenInterface
{
    private $token;

    /**
     * {@inheritdoc}
     */
    public function getToken()
    {
        return $this->token;
    }

    /**
     * {@inheritdoc}
     */
    public function setToken($token)
    {
        $this->token = $token;

        return $this;
    }
}
