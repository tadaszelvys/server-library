<?php

/*
 * The MIT License (MIT)
 *
 * Copyright (c) 2014-2016 Spomky-Labs
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file for details.
 */

namespace OAuth2\Client\Rule;

use OAuth2\Client\ClientInterface;

abstract class ClientRegistrationManagementRule implements RuleInterface
{
    /**
     * {@inheritdoc}
     */
    public function check(ClientInterface $client, array $registration_parameters)
    {
        $client->set('registration_client_uri', $this->getRegistrationClientUri($client));
        $client->set('registration_access_token', $this->getRegistrationAccessToken($client));
    }

    /**
     * @param \OAuth2\Client\ClientInterface $client
     *
     * @return string
     */
    abstract protected function getRegistrationClientUri(ClientInterface $client);

    /**
     * @param \OAuth2\Client\ClientInterface $client
     *
     * @return string
     */
    abstract protected function getRegistrationAccessToken(ClientInterface $client);
}
