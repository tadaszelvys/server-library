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
use OAuth2\Client\ClientInterface;
use OAuth2\OpenIdConnect\HasIdTokenManager;
use OAuth2\OpenIdConnect\IdTokenManagerInterface;

final class IdTokenAlgorithmsRule implements ParameterRuleInterface
{
    use HasIdTokenManager;

    /**
     * IdTokenAlgorithmsRule constructor.
     *
     * @param \OAuth2\OpenIdConnect\IdTokenManagerInterface $id_token_manager
     */
    public function __construct(IdTokenManagerInterface $id_token_manager)
    {
        $this->setIdTokenManager($id_token_manager);
    }

    /**
     * {@inheritdoc}
     */
    public function checkParameters(ClientInterface $client, array $registration_parameters, array &$metadatas)
    {
        if (!array_key_exists('id_token_encrypted_response_alg', $registration_parameters) || !array_key_exists('id_token_encrypted_response_enc', $registration_parameters)) {
            return;
        }

        Assertion::inArray($registration_parameters['id_token_encrypted_response_alg'], $this->getIdTokenManager()->getSupportedKeyEncryptionAlgorithms(), sprintf('The ID Token content encryption algorithm "%s" is not supported. Please choose one of the following algorithm: %s', $registration_parameters['id_token_encrypted_response_alg'], $this->getIdTokenManager()->getSupportedContentEncryptionAlgorithms()));
        Assertion::inArray($registration_parameters['id_token_encrypted_response_enc'], $this->getIdTokenManager()->getSupportedContentEncryptionAlgorithms(), sprintf('The ID Token key encryption algorithm "%s" is not supported. Please choose one of the following algorithm: %s', $registration_parameters['id_token_encrypted_response_enc'], $this->getIdTokenManager()->getSupportedKeyEncryptionAlgorithms()));

        $metadatas['id_token_encrypted_response_alg'] = $registration_parameters['id_token_encrypted_response_alg'];
        $metadatas['id_token_encrypted_response_enc'] = $registration_parameters['id_token_encrypted_response_enc'];
    }
}
