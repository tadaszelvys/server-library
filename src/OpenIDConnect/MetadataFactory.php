<?php

/*
 * The MIT License (MIT)
 *
 * Copyright (c) 2014-2016 Spomky-Labs
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file for details.
 */

namespace OAuth2\OpenIDConnect;

use OAuth2\Endpoint\AuthorizationEndpointInterface;
use OAuth2\Endpoint\TokenEndpointInterface;
use OAuth2\Scope\ScopeManagerInterface;
use OAuth2\Util\JWTCreator;

final class MetadataFactory
{
    /**
     * @var \OAuth2\Scope\ScopeManagerInterface
     */
    private $scope_manager;

    /**
     * @var \OAuth2\Endpoint\AuthorizationEndpointInterface
     */
    private $authorization_endpoint;

    /**
     * @var \OAuth2\Endpoint\TokenEndpointInterface
     */
    private $token_endpoint;

    /**
     * @var \OAuth2\OpenIDConnect\IdTokenManagerInterface
     */
    private $id_token_manager;

    /**
     * @var \OAuth2\OpenIDConnect\UserInfoEndpointInterface
     */
    private $user_info_endpoint;

    /**
     * @var \OAuth2\Util\JWTCreator
     */
    private $jwt_creator;

    /**
     * MetadataFactory constructor.
     *
     * @param \OAuth2\Scope\ScopeManagerInterface             $scope_manager
     * @param \OAuth2\Endpoint\AuthorizationEndpointInterface $authorization_endpoint
     * @param \OAuth2\Endpoint\TokenEndpointInterface         $token_endpoint
     * @param \OAuth2\OpenIDConnect\IdTokenManagerInterface   $id_token_manager
     * @param \OAuth2\OpenIDConnect\UserInfoEndpointInterface $user_info_endpoint
     * @param \OAuth2\Util\JWTCreator                         $jwt_creator
     */
    public function __construct(ScopeManagerInterface $scope_manager,
                                AuthorizationEndpointInterface $authorization_endpoint,
                                TokenEndpointInterface $token_endpoint,
                                IdTokenManagerInterface $id_token_manager,
                                UserInfoEndpointInterface $user_info_endpoint,
                                JWTCreator $jwt_creator
    ) {
        $this->scope_manager = $scope_manager;
        $this->authorization_endpoint = $authorization_endpoint;
        $this->token_endpoint = $token_endpoint;
        $this->id_token_manager = $id_token_manager;
        $this->user_info_endpoint = $user_info_endpoint;
        $this->jwt_creator = $jwt_creator;
    }

    public function createMetadata()
    {
        $metadata = new Metadata();

        /*$metadata->setIssuer('My Authorization Server');
        $metadata->setAuthorizationEndpoint('https://my.server.com/authorize');
        $metadata->setTokenEndpoint('https://my.server.com/authorize');
        $metadata->setUserinfoEndpoint('https://my.server.com/authorize');
        $metadata->setJwksUri('https://my.server.com/authorize');
        $metadata->setRegistrationEndpoint('https://my.server.com/authorize');*/
        $metadata->setScopesSupported($this->scope_manager->getAvailableScopes());
        $metadata->setResponseTypesSupported($this->authorization_endpoint->getResponseTypesSupported());
        $metadata->setResponseModesSupported($this->authorization_endpoint->getResponseModesSupported());
        $metadata->setGrantTypesSupported($this->token_endpoint->getGrantTypesSupported());
        //$metadata->setAcrValuesSupported('https://my.server.com/authorize');
        //$metadata->setSubjectTypesSupported('https://my.server.com/authorize');
        $metadata->setIdTokenSigningAlgValuesSupported($this->jwt_creator->getSignatureAlgorithms());
        $metadata->setIdTokenEncryptionAlgValuesSupported($this->jwt_creator->getKeyEncryptionAlgorithms());
        $metadata->setIdTokenEncryptionEncValuesSupported($this->jwt_creator->getContentEncryptionAlgorithms());
        $metadata->setUserinfoSigningAlgValuesSupported($this->jwt_creator->getSignatureAlgorithms());
        $metadata->setUserinfoEncryptionAlgValuesSupported($this->jwt_creator->getKeyEncryptionAlgorithms());
        $metadata->setUserinfoEncryptionEncValuesSupported($this->jwt_creator->getContentEncryptionAlgorithms());
        $metadata->setRequestObjectSigningAlgValuesSupported($this->jwt_creator->getSignatureAlgorithms());
        $metadata->setRequestObjectEncryptionAlgValuesSupported($this->jwt_creator->getKeyEncryptionAlgorithms());
        $metadata->setRequestObjectEncryptionEncValuesSupported($this->jwt_creator->getContentEncryptionAlgorithms());
        $metadata->setTokenEndpointAuthMethodsSupported('https://my.server.com/authorize');
        $metadata->setTokenEndpointAuthSigningAlgValuesSupported($this->jwt_creator->getSignatureAlgorithms());
        $metadata->setDisplayValuesSupported('https://my.server.com/authorize');
        $metadata->setClaimTypesSupported('https://my.server.com/authorize');
        $metadata->setClaimsSupported('https://my.server.com/authorize');
        $metadata->setServiceDocumentation('https://my.server.com/authorize');
        $metadata->setClaimsLocalesSupported('https://my.server.com/authorize');
        $metadata->setUiLocalesSupported('https://my.server.com/authorize');
        $metadata->setClaimsParameterSupported('https://my.server.com/authorize');
        $metadata->setRequestParameterSupported('https://my.server.com/authorize');
        $metadata->setRequestUriParameterSupported('https://my.server.com/authorize');
        $metadata->setRequireRequestUriRegistration('https://my.server.com/authorize');
        $metadata->setOpPolicyUri('https://my.server.com/authorize');
        $metadata->setOpTosUri('https://my.server.com/authorize');

        return $metadata;
    }
}
