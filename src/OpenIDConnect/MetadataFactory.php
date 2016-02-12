<?php

namespace OAuth2\OpenIDConnect;


use OAuth2\Endpoint\AuthorizationEndpointInterface;
use OAuth2\Endpoint\TokenEndpointInterface;
use OAuth2\Scope\ScopeManagerInterface;

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
     * MetadataFactory constructor.
     *
     * @param \OAuth2\Scope\ScopeManagerInterface             $scope_manager
     * @param \OAuth2\Endpoint\AuthorizationEndpointInterface $authorization_endpoint
     * @param \OAuth2\Endpoint\TokenEndpointInterface         $token_endpoint
     * @param \OAuth2\OpenIDConnect\IdTokenManagerInterface   $id_token_manager
     * @param \OAuth2\OpenIDConnect\UserInfoEndpointInterface $user_info_endpoint
     */
    public function __construct(ScopeManagerInterface $scope_manager,
                                AuthorizationEndpointInterface $authorization_endpoint,
                                TokenEndpointInterface $token_endpoint,
                                IdTokenManagerInterface $id_token_manager,
                                UserInfoEndpointInterface $user_info_endpoint
    ) {
        $this->scope_manager = $scope_manager;
        $this->authorization_endpoint = $authorization_endpoint;
        $this->token_endpoint = $token_endpoint;
        $this->id_token_manager = $id_token_manager;
        $this->user_info_endpoint = $user_info_endpoint;
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
        $metadata->setIdTokenSigningAlgValuesSupported('https://my.server.com/authorize');
        $metadata->setIdTokenEncryptionAlgValuesSupported('https://my.server.com/authorize');
        $metadata->setIdTokenEncryptionEncValuesSupported('https://my.server.com/authorize');
        $metadata->setUserinfoSigningAlgValuesSupported('https://my.server.com/authorize');
        $metadata->setUserinfoEncryptionAlgValuesSupported('https://my.server.com/authorize');
        $metadata->setUserinfoEncryptionEncValuesSupported('https://my.server.com/authorize');
        $metadata->setRequestObjectSigningAlgValuesSupported('https://my.server.com/authorize');
        $metadata->setRequestObjectEncryptionAlgValuesSupported('https://my.server.com/authorize');
        $metadata->setRequestObjectEncryptionEncValuesSupported('https://my.server.com/authorize');
        $metadata->setTokenEndpointAuthMethodsSupported('https://my.server.com/authorize');
        $metadata->setTokenEndpointAuthSigningAlgValuesSupported('https://my.server.com/authorize');
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
