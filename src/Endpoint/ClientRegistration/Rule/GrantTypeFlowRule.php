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
use OAuth2\Grant\GrantTypeManagerInterface;
use OAuth2\Grant\ResponseTypeManagerInterface;

final class GrantTypeFlowRule implements ClientRegistrationRuleInterface
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
    public function checkRegistrationParameters(array $registration_parameters, array &$metadatas)
    {
        if (array_key_exists('grant_types', $registration_parameters)) {
            $this->checkGrantTypes($registration_parameters, $metadatas);
        }
        if (array_key_exists('response_types', $registration_parameters)) {
            $this->checkResponseTypes($registration_parameters, $metadatas);
        }
    }

    /**
     * {@inheritdoc}
     */
    private function checkGrantTypes(array $registration_parameters, array &$metadatas)
    {
        Assertion::isArray($registration_parameters['grant_types'], 'The parameter "grant_types" must be an array of strings.');
        Assertion::allString($registration_parameters['grant_types'], 'The parameter "grant_types" must be an array of strings.');

        if (!array_key_exists('grant_types', $metadatas)) {
            $metadatas['grant_types'] = [];
        }

        foreach ($registration_parameters['grant_types'] as $grant_type) {
            $type = $this->getGrantTypeManager()->getGrantType($grant_type);
            if (!in_array($grant_type, $metadatas['grant_types'])) {
                $metadatas['grant_types'][] = $grant_type;
            }
            $associated_response_types = $type->getAssociatedResponseTypes();
            if (!empty($associated_response_types)) {
                if (!array_key_exists('response_types', $metadatas)) {
                    $metadatas['response_types'] = [];
                }
                $metadatas['response_types'] = array_unique(array_merge(
                    $metadatas['response_types'],
                    $associated_response_types
                ));
            }
        }
    }

    /**
     * {@inheritdoc}
     */
    private function checkResponseTypes(array $registration_parameters, array &$metadatas)
    {
        Assertion::isArray($registration_parameters['response_types'], 'The parameter "response_types" must be an array of strings.');
        Assertion::allString($registration_parameters['response_types'], 'The parameter "grant_types" must be an array of strings.');

        if (!array_key_exists('response_types', $metadatas)) {
            $metadatas['response_types'] = [];
        }

        foreach ($registration_parameters['response_types'] as $response_type) {
            $types = $this->getResponseTypeManager()->getResponseTypes($response_type);
            if (!in_array($response_type, $metadatas['response_types'])) {
                $metadatas['response_types'][] = $response_type;
            }
            foreach ($types as $type) {
                $associated_grant_types = $type->getAssociatedGrantTypes();
                if (!empty($associated_grant_types)) {
                    if (!array_key_exists('grant_types', $metadatas)) {
                        $metadatas['grant_types'] = [];
                    }
                    $metadatas['grant_types'] = array_unique(array_merge(
                        $metadatas['grant_types'],
                        $associated_grant_types
                    ));
                }
            }
        }
    }
}
