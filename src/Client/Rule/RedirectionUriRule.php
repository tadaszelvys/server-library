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

use Assert\Assertion;
use OAuth2\Client\ClientInterface;

final class RedirectionUriRule implements RuleInterface
{
    /**
     * {@inheritdoc}
     */
    public function check(ClientInterface $client, array $registration_parameters)
    {
        if (!array_key_exists('redirect_uris', $registration_parameters)) {
            return;
        }
        Assertion::isArray($registration_parameters['redirect_uris'], 'The parameter "redirect_uris" must be a list of URI.');
        Assertion::allUrl($registration_parameters['redirect_uris'], 'The parameter "redirect_uris" must be a list of URI.');
        $client->set('redirect_uris', $registration_parameters['redirect_uris']);
    }
}
