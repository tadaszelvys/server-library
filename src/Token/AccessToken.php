<?php

namespace OAuth2\Token;

class AccessToken extends Token implements AccessTokenInterface
{
    /**
     * @var null|string
     */
    protected $refresh_token;

    /**
     * {@inheritdoc}
     */
    public function getRefreshToken()
    {
        return $this->refresh_token;
    }

    /**
     * @param string|null $refresh_token
     *
     * @return self
     */
    public function setRefreshToken($refresh_token)
    {
        $this->refresh_token = $refresh_token;

        return $this;
    }

    public function jsonSerialize()
    {
        $values = [
           'access_token' => $this->getToken(),
           'expires_in'   => $this->getExpiresIn(),
           'scope'        => count($this->getScope()) ? implode(' ', $this->getScope()) : null,
        ];

        if (!empty($this->getRefreshToken())) {
            $values['refresh_token'] = $this->getRefreshToken();
        }

        return $values;
    }
}