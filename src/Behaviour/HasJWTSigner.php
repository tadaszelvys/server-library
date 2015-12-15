<?php

namespace OAuth2\Behaviour;

use OAuth2\Util\JWTSigner;

trait HasJWTSigner
{
    /**
     * @var \OAuth2\Util\JWTSigner
     */
    private $jwt_signer;

    /**
     * @return \OAuth2\Util\JWTSigner
     */
    protected function getJWTSigner()
    {
        return $this->jwt_signer;
    }

    /**
     * @param \OAuth2\Util\JWTSigner $jwt_signer
     */
    private function setJWTSigner(JWTSigner $jwt_signer)
    {
        $this->jwt_signer = $jwt_signer;
    }
}
