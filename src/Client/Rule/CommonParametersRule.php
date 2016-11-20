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

class CommonParametersRule extends AbstractInternationalizedRule
{
    /**
     * {@inheritdoc}
     */
    public function check(ClientInterface $client, array $registration_parameters)
    {
        $metadatas = [];
        foreach ($this->getSupportedParameters() as $parameter => $closure) {
            $metadatas = array_merge(
                $metadatas,
                $this->getInternationalizedParameters($registration_parameters, $parameter, $closure)
            );
        }
        foreach ($metadatas as $k => $v) {
            $client->set($k, $v);
        }
    }

    /**
     * {@inheritdoc}
     */
    public function getPreserverParameters()
    {
        return [];
    }

    /**
     * @return array
     */
    private function getSupportedParameters()
    {
        return [
            'client_name' => function ($k, $v) {
            },
            'client_uri'  => $this->getUriVerificationClosure(),
            'logo_uri'    => $this->getUriVerificationClosure(),
            'tos_uri'     => $this->getUriVerificationClosure(),
            'policy_uri'  => $this->getUriVerificationClosure(),
        ];
    }

    private function getUriVerificationClosure()
    {
        return function ($k, $v) {
            Assertion::url($v, sprintf('The parameter with key "%s" is not a valid URL.', $k));
        };
    }
}
