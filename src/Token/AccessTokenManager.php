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

use OAuth2\Behaviour\HasConfiguration;
use OAuth2\Client\ClientInterface;
use OAuth2\Client\TokenLifetimeExtensionInterface;
use OAuth2\Configuration\ConfigurationInterface;

abstract class AccessTokenManager implements AccessTokenManagerInterface
{
    use HasConfiguration;

    /**
     * AccessTokenManager constructor.
     *
     * @param \OAuth2\Configuration\ConfigurationInterface $configuration
     */
    public function __construct(ConfigurationInterface $configuration)
    {
        $this->setConfiguration($configuration);
    }

    /**
     * @param \OAuth2\Client\ClientInterface $client Client
     *
     * @return int
     */
    protected function getLifetime(ClientInterface $client)
    {
        $lifetime = $this->getConfiguration()->get('access_token_lifetime', 3600);
        if ($client instanceof TokenLifetimeExtensionInterface && is_int($_lifetime = $client->getTokenLifetime('access_token'))) {
            return $_lifetime;
        }

        return $lifetime;
    }

    /**
     * We only check if the token has not expired.
     * This method should be overridden to verify the client or the resource owner are enabled for example.
     *
     * {@inheritdoc}
     */
    public function isAccessTokenValid(AccessTokenInterface $token)
    {
        return !$token->hasExpired();
    }
}
