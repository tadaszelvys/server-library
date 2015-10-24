<?php

namespace OAuth2\Behaviour;

use OAuth2\Util\JWTSigner;

trait HasJWTSigner
{
    /**
     * @var \OAuth2\Util\JWTSigner
     */
    protected $jwt_signer;

    /**
     * @return \OAuth2\Util\JWTSigner
     */
    public function getJWTSigner()
    {
        return $this->jwt_signer;
    }

    /**
     * @param \OAuth2\Util\JWTSigner $jwt_signer
     *
     * @return self
     */
    public function setJWTSigner(JWTSigner $jwt_signer)
    {
        $this->jwt_signer = $jwt_signer;

        return $this;
    }
}
