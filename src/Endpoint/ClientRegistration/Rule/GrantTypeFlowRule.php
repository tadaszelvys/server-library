<?php

/*
 * The MIT License (MIT)
 *
 * Copyright (c) 2014-2016 Spomky-Labs
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file for details.
 */

namespace OAuth2\Endpoint\ClientRegistration\Rule;

use Assert\Assertion;
use OAuth2\Behaviour\HasGrantTypeManager;
use OAuth2\Behaviour\HasResponseTypeManager;
use OAuth2\Client\ClientInterface;
use OAuth2\Grant\GrantTypeManagerInterface;
use OAuth2\Grant\ResponseTypeManagerInterface;

final class GrantTypeFlowRule implements ParameterRuleInterface
{
    use HasResponseTypeManager;
    use HasGrantTypeManager;

    public function __construct(GrantTypeManagerInterface $grant_type_manager, ResponseTypeManagerInterface $response_type_manager)
    {
        $this->setGrantTypeManager($grant_type_manager);
        $this->setResponseTypeManager($response_type_manager);
    }

    /**
     * {@inheritdoc}
     */
    public function checkParameters(ClientInterface $client, array $registration_parameters, array &$metadatas)
    {
        $metadatas['response_types'] = [];
        $metadatas['grant_types'] = [];

        if (!array_key_exists('grant_types', $registration_parameters)) {
            $registration_parameters['grant_types'] = [];
        }
        if (!array_key_exists('response_types', $registration_parameters)) {
            $registration_parameters['response_types'] = [];
        }
        $this->checkGrantTypes($registration_parameters, $metadatas);
        $this->checkResponseTypes($registration_parameters, $metadatas);
    }

    /**
     * {@inheritdoc}
     */
    private function checkGrantTypes(array $registration_parameters, array &$metadatas)
    {
        Assertion::isArray($registration_parameters['grant_types'], 'The parameter "grant_types" must be an array of strings.');
        Assertion::allString($registration_parameters['grant_types'], 'The parameter "grant_types" must be an array of strings.');

        foreach ($registration_parameters['grant_types'] as $grant_type) {
            $type = $this->getGrantTypeManager()->getGrantType($grant_type);
            if (!in_array($grant_type, $metadatas['grant_types'])) {
                $metadatas['grant_types'][] = $grant_type;
            }
            $associated_response_types = $type->getAssociatedResponseTypes();
            $diff = array_diff($associated_response_types, $registration_parameters['response_types']);
            Assertion::true(empty($diff), sprintf('The grant type "%s" is associated with the response types "%s" but this response type is missing.', $type->getGrantType(), json_encode($diff)));

            $metadatas['response_types'] = array_unique(array_merge($metadatas['response_types'], $associated_response_types));
        }
    }

    /**
     * {@inheritdoc}
     */
    private function checkResponseTypes(array $registration_parameters, array &$metadatas)
    {
        Assertion::isArray($registration_parameters['response_types'], 'The parameter "response_types" must be an array of strings.');
        Assertion::allString($registration_parameters['response_types'], 'The parameter "grant_types" must be an array of strings.');

        foreach ($registration_parameters['response_types'] as $response_type) {
            $types = $this->getResponseTypeManager()->getResponseTypes($response_type);
            if (!in_array($response_type, $metadatas['response_types'])) {
                $metadatas['response_types'][] = $response_type;
            }
            foreach ($types as $type) {
                $associated_grant_types = $type->getAssociatedGrantTypes();
                $diff = array_diff($associated_grant_types, $registration_parameters['grant_types']);
                Assertion::true(empty($diff), sprintf('The response type "%s" is associated with the grant types "%s" but this response type is missing.', $type->getResponseType(), json_encode($diff)));

                $metadatas['grant_types'] = array_unique(array_merge($metadatas['grant_types'], $associated_grant_types));
            }
        }
    }
}
