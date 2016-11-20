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
use OAuth2\Behaviour\HasGrantTypeManager;
use OAuth2\Behaviour\HasResponseTypeManager;
use OAuth2\Client\ClientInterface;
use OAuth2\Grant\GrantTypeManagerInterface;
use OAuth2\Grant\ResponseTypeManagerInterface;

class GrantTypeFlowRule implements RuleInterface
{
    use HasResponseTypeManager;
    use HasGrantTypeManager;

    /**
     * GrantTypeFlowRule constructor.
     *
     * @param \OAuth2\Grant\GrantTypeManagerInterface    $grant_type_manager
     * @param \OAuth2\Grant\ResponseTypeManagerInterface $response_type_manager
     */
    public function __construct(GrantTypeManagerInterface $grant_type_manager, ResponseTypeManagerInterface $response_type_manager)
    {
        $this->setGrantTypeManager($grant_type_manager);
        $this->setResponseTypeManager($response_type_manager);
    }

    /**
     * {@inheritdoc}
     */
    public function getPreserverParameters()
    {
        return [];
    }

    /**
     * {@inheritdoc}
     */
    public function check(ClientInterface $client, array $registration_parameters)
    {
        $client->set('response_types', []);
        $client->set('grant_types', []);

        if (!array_key_exists('grant_types', $registration_parameters)) {
            $registration_parameters['grant_types'] = [];
        }
        if (!array_key_exists('response_types', $registration_parameters)) {
            $registration_parameters['response_types'] = [];
        }
        $this->checkGrantTypes($client, $registration_parameters);
        $this->checkResponseTypes($client, $registration_parameters);
    }

    /**
     * @param \OAuth2\Client\ClientInterface $client
     * @param array                          $registration_parameters
     */
    private function checkGrantTypes(ClientInterface $client, array $registration_parameters)
    {
        Assertion::isArray($registration_parameters['grant_types'], 'The parameter "grant_types" must be an array of strings.');
        Assertion::allString($registration_parameters['grant_types'], 'The parameter "grant_types" must be an array of strings.');

        foreach ($registration_parameters['grant_types'] as $grant_type) {
            $type = $this->getGrantTypeManager()->getGrantType($grant_type);
            if (!in_array($grant_type, $client->get('grant_types'))) {
                $grant_types = $client->get('grant_types');
                $grant_types[] = $grant_type;
                $client->set('grant_types', $grant_types);
            }
            $associated_response_types = $type->getAssociatedResponseTypes();
            $diff = array_diff($associated_response_types, $registration_parameters['response_types']);
            Assertion::true(empty($diff), sprintf('The grant type "%s" is associated with the response types "%s" but this response type is missing.', $type->getGrantType(), json_encode($diff)));

            $client->set('response_types', array_unique(array_merge($client->get('response_types'), $associated_response_types)));
        }
    }

    /**
     * @param \OAuth2\Client\ClientInterface $client
     * @param array                          $registration_parameters
     */
    private function checkResponseTypes(ClientInterface $client, array $registration_parameters)
    {
        Assertion::isArray($registration_parameters['response_types'], 'The parameter "response_types" must be an array of strings.');
        Assertion::allString($registration_parameters['response_types'], 'The parameter "grant_types" must be an array of strings.');

        foreach ($registration_parameters['response_types'] as $response_type) {
            $types = $this->getResponseTypeManager()->getResponseTypes($response_type);
            if (!in_array($response_type, $client->get('response_types'))) {
                $response_types = $client->get('response_types');
                $response_types[] = $response_type;
                $client->set('response_types', $response_types);
            }
            foreach ($types as $type) {
                $associated_grant_types = $type->getAssociatedGrantTypes();
                $diff = array_diff($associated_grant_types, $registration_parameters['grant_types']);
                Assertion::true(empty($diff), sprintf('The response type "%s" is associated with the grant types "%s" but this response type is missing.', $type->getResponseType(), json_encode($diff)));

                $client->set('grant_types', array_unique(array_merge($client->get('grant_types'), $associated_grant_types)));
            }
        }
    }
}
