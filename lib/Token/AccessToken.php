<?php

namespace OAuth2\Token;

abstract class AccessToken implements AccessTokenInterface
{
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
