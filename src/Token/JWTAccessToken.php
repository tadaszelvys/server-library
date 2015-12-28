<?php

/*
 * The MIT License (MIT)
 *
 * Copyright (c) 2014-2015 Spomky-Labs
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file for details.
 */

namespace OAuth2\Token;

use Jose\Object\JWSInterface;

class JWTAccessToken extends AccessToken implements JWTAccessTokenInterface
{
    /**
     * @var \Jose\Object\JWSInterface
     */
    private $jws = null;

    /**
     * {@inheritdoc}
     */
    public function setJWS(JWSInterface $jws)
    {
        $this->jws = $jws;
    }

    /**
     * {@inheritdoc}
     */
    public function getJWS()
    {
        return $this->jws;
    }

    /**
     * {@inheritdoc}
     */
    public function getTokenType()
    {
        return $this->jws->getClaim('aty');
    }

    /**
     * {@inheritdoc}
     */
    public function getRefreshToken()
    {
        if ($this->jws->hasClaim('ref')) {
            return $this->jws->getClaim('ref');
        }
    }

    /**
     * {@inheritdoc}
     */
    public function getClientPublicId()
    {
        return $this->jws->getClaim('sub');
    }

    /**
     * {@inheritdoc}
     */
    public function getScope()
    {
        if ($this->jws->hasClaim('sco')) {
            return $this->jws->getClaim('sco');
        }
    }

    /**
     * {@inheritdoc}
     */
    public function getResourceOwnerPublicId()
    {
        return $this->jws->getClaim('r_o');
    }

    /**
     * {@inheritdoc}
     */
    public function getExpiresAt()
    {
        return $this->jws->getClaim('exp');
    }

    /**
     * {@inheritdoc}
     */
    public function getParameters()
    {
        if ($this->jws->hasClaim('oth')) {
            return $this->jws->getClaim('oth');
        }
    }
}
