<?php

/*
 * The MIT License (MIT)
 *
 * Copyright (c) 2014-2016 Spomky-Labs
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file for details.
 */

namespace OAuth2\Test;

use Jose\Checker\AudienceChecker;
use Jose\Decrypter;
use Jose\Encrypter;
use Jose\Factory\CheckerManagerFactory;
use Jose\Object\JWK;
use Jose\Object\JWKSet;
use Jose\Signer;
use Jose\Verifier;
use OAuth2\Client\AuthenticationMethod\ClientAssertionJwt;
use OAuth2\Client\AuthenticationMethod\ClientSecretBasic;
use OAuth2\Client\AuthenticationMethod\ClientSecretPost;
use OAuth2\Client\AuthenticationMethod\None;
use OAuth2\Endpoint\AuthorizationEndpoint;
use OAuth2\Endpoint\AuthorizationFactory;
use OAuth2\Endpoint\FragmentResponseMode;
use OAuth2\Endpoint\QueryResponseMode;
use OAuth2\Endpoint\TokenEndpoint;
use OAuth2\Endpoint\TokenIntrospectionEndpoint;
use OAuth2\Endpoint\TokenRevocationEndpoint;
use OAuth2\Endpoint\TokenType\AccessToken;
use OAuth2\Endpoint\TokenType\RefreshToken;
use OAuth2\Exception\ExceptionManager;
use OAuth2\Grant\AuthorizationCodeGrantType;
use OAuth2\Grant\ClientCredentialsGrantType;
use OAuth2\Grant\ImplicitGrantType;
use OAuth2\Grant\JWTBearerGrantType;
use OAuth2\Grant\RefreshTokenGrantType;
use OAuth2\Grant\ResourceOwnerPasswordCredentialsGrantType;
use OAuth2\OpenIDConnect\FormPostResponseMode;
use OAuth2\OpenIDConnect\IdTokenGrantType;
use OAuth2\OpenIDConnect\IdTokenManager;
use OAuth2\OpenIDConnect\Metadata;
use OAuth2\OpenIDConnect\NoneResponseType;
use OAuth2\OpenIDConnect\OpenIDConnectTokenEndpointExtension;
use OAuth2\OpenIDConnect\Pairwise\HashedSubjectIdentifier;
use OAuth2\OpenIDConnect\UserInfo;
use OAuth2\OpenIDConnect\UserInfoEndpoint;
use OAuth2\OpenIDConnect\UserinfoScopeSupport\AddressScopeSupport;
use OAuth2\OpenIDConnect\UserinfoScopeSupport\EmailScopeSupport;
use OAuth2\OpenIDConnect\UserinfoScopeSupport\PhoneScopeSupport;
use OAuth2\OpenIDConnect\UserinfoScopeSupport\ProfilScopeSupport;
use OAuth2\Scope\DefaultScopePolicy;
use OAuth2\Scope\ErrorScopePolicy;
use OAuth2\Security\EntryPoint;
use OAuth2\Security\Listener;
use OAuth2\Test\Stub\AuthCodeManager;
use OAuth2\Test\Stub\ClientManager;
use OAuth2\Test\Stub\FooBarAccessTokenUpdater;
use OAuth2\Test\Stub\JWTAccessTokenManager;
use OAuth2\Test\Stub\NoneListener;
use OAuth2\Test\Stub\RefreshTokenManager;
use OAuth2\Test\Stub\ResourceServerManager;
use OAuth2\Test\Stub\ScopeManager;
use OAuth2\Test\Stub\TooManyRequestsException;
use OAuth2\Test\Stub\UriExtension;
use OAuth2\Test\Stub\UserManager;
use OAuth2\Token\BearerToken;
use OAuth2\Token\MacToken;
use OAuth2\Token\TokenTypeManager;
use Jose\JWTCreator;
use Jose\JWTLoader;
use Symfony\Bridge\PsrHttpMessage\Factory\DiactorosFactory;
use Symfony\Component\HttpFoundation\Request;

class Base extends \PHPUnit_Framework_TestCase
{
    /**
     * @var string
     */
    private $realm = 'testrealm@host.com';

    /**
     * @var string
     */
    private $issuer = 'https://server.example.com';

    /**
     * @var string
     */
    private $pairwise_key = 'This is my secret Key !!!';

    /**
     * @var string
     */
    private $pairwise_additional_data = 'This is my salt or my IV !!!';

    protected function setUp()
    {
        //To fix HHVM tests on Travis-CI
        date_default_timezone_set('UTC');
    }

    /**
     * @return string
     */
    protected function getIssuer()
    {
        return $this->issuer;
    }

    /**
     * @return string
     */
    protected function getPairwiseKey()
    {
        return $this->pairwise_key;
    }

    /**
     * @return string
     */
    protected function getPairwiseAdditionalData()
    {
        return mb_substr($this->pairwise_additional_data, 0, 16, '8bit');
    }

    /**
     * @param string      $uri
     * @param string      $method
     * @param array       $parameters
     * @param array       $server
     * @param array       $headers
     * @param null|string $content
     *
     * @return \Psr\Http\Message\ServerRequestInterface
     */
    protected function createRequest($uri = '/', $method = 'GET', array $parameters = [], array $server = [], array $headers = [], $content = null)
    {
        $request = Request::create($uri, $method, $parameters, [], [], $server, $content);
        foreach ($headers as $key => $value) {
            $request->headers->set($key, $value);
        }

        $factory = new DiactorosFactory();

        return $factory->createRequest($request);
    }

    /**
     * @var \OAuth2\Endpoint\AuthorizationFactory
     */
    private $authorization_factory;

    /**
     * @return \OAuth2\Endpoint\AuthorizationFactory
     */
    protected function getAuthorizationFactory()
    {
        if (null === $this->authorization_factory) {
            $this->authorization_factory = new AuthorizationFactory(
                $this->getScopeManager(),
                $this->getClientManager(),
                $this->getExceptionManager()
            );

            $this->authorization_factory->enableRequestObjectSupport(
                $this->getJWTLoader()
            );
            $this->authorization_factory->enableRequestObjectReferenceSupport();

            $this->authorization_factory->enableEncryptedRequestObjectSupport(
                new JWKSet(['keys' => [
                    [
                        'kid' => 'JWK1',
                        'use' => 'enc',
                        'kty' => 'oct',
                        'k'   => 'ABEiM0RVZneImaq7zN3u_wABAgMEBQYHCAkKCwwNDg8',
                    ],
                ]])
            );
        }

        return $this->authorization_factory;
    }

    /**
     * @var null|\OAuth2\Endpoint\TokenRevocationEndpointInterface
     */
    private $revocation_endpoint = null;

    /**
     * @return \OAuth2\Endpoint\TokenRevocationEndpointInterface
     */
    protected function getRevocationTokenEndpoint()
    {
        if (null === $this->revocation_endpoint) {
            $this->revocation_endpoint = new TokenRevocationEndpoint(
                $this->getClientManager(),
                $this->getExceptionManager()
            );

            $this->revocation_endpoint->addRevocationTokenType($this->getAccessTokenType());
            $this->revocation_endpoint->addRevocationTokenType($this->getRefreshTokenType());
        }

        return $this->revocation_endpoint;
    }

    /**
     * @var null|\OAuth2\OpenIDConnect\UserInfoInterface
     */
    private $userinfo = null;

    /**
     * @return \OAuth2\OpenIDConnect\UserInfoInterface
     */
    protected function getUserInfo()
    {
        if (null === $this->userinfo) {
            $this->userinfo = new UserInfo(
                $this->getUserManager(),
                $this->getClientManager(),
                $this->getExceptionManager()
            );

            $this->userinfo->addUserInfoScopeSupport(new ProfilScopeSupport());
            $this->userinfo->addUserInfoScopeSupport(new AddressScopeSupport());
            $this->userinfo->addUserInfoScopeSupport(new EmailScopeSupport());
            $this->userinfo->addUserInfoScopeSupport(new PhoneScopeSupport());

            $this->userinfo->enablePairwiseSubject(new HashedSubjectIdentifier($this->getPairwiseKey(), 'sha512', $this->getPairwiseAdditionalData()));
        }

        return $this->userinfo;
    }

    /**
     * @var null|\OAuth2\OpenIDConnect\UserInfoEndpointInterface
     */
    private $userinfo_endpoint = null;

    /**
     * @return \OAuth2\OpenIDConnect\UserInfoEndpointInterface
     */
    protected function getUserInfoEndpoint()
    {
        if (null === $this->userinfo_endpoint) {
            $this->userinfo_endpoint = new UserInfoEndpoint(
                $this->getUserManager(),
                $this->getClientManager(),
                $this->getUserInfo(),
                $this->getExceptionManager()
            );

            $this->userinfo_endpoint->enableSignedResponsesSupport(
                $this->getJWTCreator(),
                $this->getIssuer(),
                'HS512',
                new JWK([
                    'kid' => 'JWK2',
                    'use' => 'sig',
                    'kty' => 'oct',
                    'k'   => 'AyM1SysPpbyDfgZld3umj1qzKObwVMkoqQ-EstJQLr_T-1qS0gZH75aKtMN3Yj0iPS4hcgUuTwjAzZr1Z9CAow',
                ])
            );
        }

        return $this->userinfo_endpoint;
    }

    /**
     * @var null|\OAuth2\Security\ListenerInterface
     */
    private $listener = null;

    /**
     * @return \OAuth2\Security\ListenerInterface
     */
    protected function getListener()
    {
        if (null === $this->listener) {
            $this->listener = new Listener(
                $this->getTokenTypeManager(),
                $this->getJWTAccessTokenManager(),
                $this->getExceptionManager()
            );
        }

        return $this->listener;
    }

    /**
     * @var null|\OAuth2\Security\EntryPointInterface
     */
    private $entry_point = null;

    /**
     * @return \OAuth2\Security\EntryPointInterface
     */
    protected function getEntryPoint()
    {
        if (null === $this->entry_point) {
            $this->entry_point = new EntryPoint(
                $this->getTokenTypeManager(),
                $this->getExceptionManager()
            );
        }

        return $this->entry_point;
    }

    /**
     * @var null|\OAuth2\Endpoint\TokenIntrospectionEndpoint
     */
    private $token_introspection_endpoint = null;

    /**
     * @return \OAuth2\Endpoint\TokenIntrospectionEndpoint
     */
    protected function getTokenIntrospectionEndpoint()
    {
        if (null === $this->token_introspection_endpoint) {
            $this->token_introspection_endpoint = new TokenIntrospectionEndpoint(
                $this->getClientManager(),
                $this->getExceptionManager()
            );

            $this->token_introspection_endpoint->addIntrospectionTokenType($this->getAccessTokenType());
            $this->token_introspection_endpoint->addIntrospectionTokenType($this->getRefreshTokenType());
        }

        return $this->token_introspection_endpoint;
    }

    /**
     * @var null|\OAuth2\Endpoint\TokenEndpoint
     */
    private $token_endpoint = null;

    /**
     * @return \OAuth2\Endpoint\TokenEndpoint
     */
    protected function getTokenEndpoint()
    {
        if (null === $this->token_endpoint) {
            $this->token_endpoint = new TokenEndpoint(
                $this->getTokenTypeManager(),
                $this->getJWTAccessTokenManager(),
                $this->getClientManager(),
                $this->getUserManager(),
                $this->getScopeManager(),
                $this->getExceptionManager(),
                $this->getRefreshTokenManager()
            );

            $this->token_endpoint->addGrantType($this->getAuthorizationCodeGrantType());
            $this->token_endpoint->addGrantType($this->getAuthorizationCodeGrantType());
            $this->token_endpoint->addGrantType($this->getClientCredentialsGrantType());
            $this->token_endpoint->addGrantType($this->getRefreshTokenGrantType());
            $this->token_endpoint->addGrantType($this->getResourceOwnerPasswordCredentialsGrantType());
            $this->token_endpoint->addGrantType($this->getJWTBearerGrantType());

            $this->token_endpoint->addTokenEndpointExtension($this->getOpenIDConnectTokenEndpointExtension());

            $this->token_endpoint->allowAccessTokenTypeParameter();
        }

        return $this->token_endpoint;
    }

    /**
     * @var null|\OAuth2\OpenIDConnect\OpenIDConnectTokenEndpointExtension
     */
    private $openid_connect_token_endpoint_extension = null;

    /**
     * @return \OAuth2\OpenIDConnect\OpenIDConnectTokenEndpointExtension
     */
    protected function getOpenIDConnectTokenEndpointExtension()
    {
        if (null === $this->openid_connect_token_endpoint_extension) {
            $this->openid_connect_token_endpoint_extension = new OpenIDConnectTokenEndpointExtension(
                $this->getIdTokenManager(),
                $this->getUserManager()
            );
        }

        return $this->openid_connect_token_endpoint_extension;
    }

    /**
     * @var null|\OAuth2\Endpoint\AuthorizationEndpoint
     */
    private $authorization_endpoint = null;

    /**
     * @return \OAuth2\Endpoint\AuthorizationEndpoint
     */
    protected function getAuthorizationEndpoint()
    {
        if (null === $this->authorization_endpoint) {
            $this->authorization_endpoint = new AuthorizationEndpoint(
                $this->getScopeManager(),
                $this->getExceptionManager()
            );

            $this->authorization_endpoint->addResponseType($this->getAuthorizationCodeGrantType());
            $this->authorization_endpoint->addResponseType($this->getImplicitGrantType());
            $this->authorization_endpoint->addResponseType($this->getNoneResponseType());
            $this->authorization_endpoint->addResponseType($this->getIdTokenGrantType());

            $this->authorization_endpoint->addResponseMode(new QueryResponseMode());
            $this->authorization_endpoint->addResponseMode(new FragmentResponseMode());
            $this->authorization_endpoint->addResponseMode(new FormPostResponseMode());

            $this->authorization_endpoint->allowResponseModeParameterInAuthorizationRequest();
            $this->authorization_endpoint->disallowResponseModeParameterInAuthorizationRequest();
            $this->authorization_endpoint->allowResponseModeParameterInAuthorizationRequest();
            $this->authorization_endpoint->enableStateParameterEnforcement();
            $this->authorization_endpoint->disableStateParameterEnforcement();
            $this->authorization_endpoint->enableStateParameterEnforcement();
        }

        return $this->authorization_endpoint;
    }

    /**
     * @var null|\OAuth2\Exception\ExceptionManagerInterface
     */
    private $exception_manager = null;

    /**
     * @return \OAuth2\Exception\ExceptionManagerInterface
     */
    protected function getExceptionManager()
    {
        if (null === $this->exception_manager) {
            $this->exception_manager = new ExceptionManager();
            $this->exception_manager->addExtension(new UriExtension());
            $this->exception_manager->addExceptionType('TooManyRequests', TooManyRequestsException::class);
        }

        return $this->exception_manager;
    }

    /**
     * @var null|\OAuth2\Test\Stub\UserManager
     */
    private $user_manager = null;

    /**
     * @return \OAuth2\Test\Stub\UserManager
     */
    protected function getUserManager()
    {
        if (null === $this->user_manager) {
            $this->user_manager = new UserManager();
        }

        return $this->user_manager;
    }

    /**
     * @var null|\OAuth2\Client\ClientManager
     */
    private $client_manager = null;

    /**
     * @return \OAuth2\Client\ClientManager
     */
    protected function getClientManager()
    {
        if (null === $this->client_manager) {
            $this->client_manager = new ClientManager($this->getExceptionManager());

            $jwt_assertion = new ClientAssertionJwt($this->getJWTLoader(), $this->getExceptionManager());
            $jwt_assertion->enableEncryptedAssertions(
                false,
                new JWKSet(['keys' => [
                    [
                        'kid' => 'JWK1',
                        'use' => 'enc',
                        'kty' => 'oct',
                        'k'   => 'ABEiM0RVZneImaq7zN3u_wABAgMEBQYHCAkKCwwNDg8',
                    ],
                ]])
            );

            $this->client_manager->addAuthenticationMethod(new None());
            $this->client_manager->addAuthenticationMethod(new ClientSecretBasic($this->realm));
            $this->client_manager->addAuthenticationMethod(new ClientSecretPost());
            $this->client_manager->addAuthenticationMethod($jwt_assertion);
        }

        return $this->client_manager;
    }

    /**
     * @var null|\OAuth2\Test\Stub\ResourceServerManager
     */
    private $resource_server_manager = null;

    /**
     * @return \OAuth2\Test\Stub\ResourceServerManager
     */
    protected function getResourceServerManager()
    {
        if (null === $this->resource_server_manager) {
            $this->resource_server_manager = new ResourceServerManager();

            $this->resource_server_manager->createResourceServers();
        }

        return $this->resource_server_manager;
    }

    /**
     * @var null|\OAuth2\Grant\AuthorizationCodeGrantType
     */
    private $authorization_code_grant_type = null;

    /**
     * @return \OAuth2\Grant\AuthorizationCodeGrantType
     */
    protected function getAuthorizationCodeGrantType()
    {
        if (null === $this->authorization_code_grant_type) {
            $this->authorization_code_grant_type = new AuthorizationCodeGrantType(
                $this->getAuthCodeManager(),
                $this->getExceptionManager(),
                $this->getScopeManager()
            );

            $this->authorization_code_grant_type->enablePKCEForPublicClientsEnforcement();
            $this->authorization_code_grant_type->disablePKCEForPublicClientsEnforcement();
            $this->authorization_code_grant_type->enablePKCEForPublicClientsEnforcement();
        }

        return $this->authorization_code_grant_type;
    }

    /**
     * @var null|\OAuth2\Grant\ClientCredentialsGrantType
     */
    private $client_credentials_grant_type = null;

    /**
     * @return \OAuth2\Grant\ClientCredentialsGrantType
     */
    protected function getClientCredentialsGrantType()
    {
        if (null === $this->client_credentials_grant_type) {
            $this->client_credentials_grant_type = new ClientCredentialsGrantType(
                $this->getExceptionManager()
            );
            $this->client_credentials_grant_type->enableRefreshTokenIssuanceWithAccessToken();
            $this->client_credentials_grant_type->disableRefreshTokenIssuanceWithAccessToken();
            $this->client_credentials_grant_type->enableRefreshTokenIssuanceWithAccessToken();
        }

        return $this->client_credentials_grant_type;
    }

    /**
     * @var null|\OAuth2\Grant\JWTBearerGrantType
     */
    private $jwt_bearer_grant_type = null;

    /**
     * @return \OAuth2\Grant\JWTBearerGrantType
     */
    protected function getJWTBearerGrantType()
    {
        if (null === $this->jwt_bearer_grant_type) {
            $key_encryption_key_set = new JWKSet(['keys' => [
                [
                    'kid' => 'JWK1',
                    'use' => 'enc',
                    'kty' => 'oct',
                    'k'   => 'ABEiM0RVZneImaq7zN3u_wABAgMEBQYHCAkKCwwNDg8',
                ],
            ]]);

            $this->jwt_bearer_grant_type = new JWTBearerGrantType(
                $this->getJWTLoader(),
                $this->getExceptionManager()

            );
            $this->jwt_bearer_grant_type->enableEncryptedAssertions(
                true,
                $key_encryption_key_set
            );
            $this->jwt_bearer_grant_type->disableRefreshTokenIssuanceWithAccessToken();
        }

        return $this->jwt_bearer_grant_type;
    }

    /**
     * @var null|\OAuth2\Test\Stub\NoneListener
     */
    private $none_listener = null;

    /**
     * @return \OAuth2\Test\Stub\NoneListener
     */
    public function getNoneListener()
    {
        if (null === $this->none_listener) {
            $this->none_listener = new NoneListener();
        }

        return $this->none_listener;
    }

    /**
     * @var null|\OAuth2\OpenIDConnect\NoneResponseType
     */
    private $none_response_type = null;

    /**
     * @return \OAuth2\OpenIDConnect\NoneResponseType
     */
    protected function getNoneResponseType()
    {
        if (null === $this->none_response_type) {
            $this->none_response_type = new NoneResponseType(
                $this->getTokenTypeManager(),
                $this->getJWTAccessTokenManager()
            );

            $this->none_response_type->addListener($this->getNoneListener());
            $this->none_response_type->allowAccessTokenTypeParameter();
        }

        return $this->none_response_type;
    }

    /**
     * @var null|\OAuth2\OpenIDConnect\IdTokenGrantType
     */
    private $id_token_type = null;

    /**
     * @return \OAuth2\OpenIDConnect\IdTokenGrantType
     */
    protected function getIdTokenGrantType()
    {
        if (null === $this->id_token_type) {
            $this->id_token_type = new IdTokenGrantType(
                $this->getTokenTypeManager(),
                $this->getIdTokenManager(),
                $this->getExceptionManager()
            );
        }

        return $this->id_token_type;
    }

    /**
     * @var null|\OAuth2\Grant\ImplicitGrantType
     */
    private $implicit_grant_type = null;

    /**
     * @return \OAuth2\Grant\ImplicitGrantType
     */
    protected function getImplicitGrantType()
    {
        if (null === $this->implicit_grant_type) {
            $this->implicit_grant_type = new ImplicitGrantType(
                $this->getTokenTypeManager(),
                $this->getJWTAccessTokenManager()
            );
            $this->implicit_grant_type->disallowAccessTokenTypeParameter();
        }

        return $this->implicit_grant_type;
    }

    /**
     * @var null|\OAuth2\Grant\RefreshTokenGrantType
     */
    private $refresh_token_grant_type = null;

    /**
     * @return \OAuth2\Grant\RefreshTokenGrantType
     */
    protected function getRefreshTokenGrantType()
    {
        if (null === $this->refresh_token_grant_type) {
            $this->refresh_token_grant_type = new RefreshTokenGrantType(
                $this->getRefreshTokenManager(),
                $this->getExceptionManager()
            );
        }

        return $this->refresh_token_grant_type;
    }

    /**
     * @return null|\OAuth2\Grant\ResourceOwnerPasswordCredentialsGrantType
     */
    private $resource_owner_password_credentials_grant_type = null;

    /**
     * @return \OAuth2\Grant\ResourceOwnerPasswordCredentialsGrantType
     */
    protected function getResourceOwnerPasswordCredentialsGrantType()
    {
        if (null === $this->resource_owner_password_credentials_grant_type) {
            $this->resource_owner_password_credentials_grant_type = new ResourceOwnerPasswordCredentialsGrantType(
                $this->getUserManager(),
                $this->getExceptionManager()
            );
            $this->resource_owner_password_credentials_grant_type->enableRefreshTokenIssuanceWithAccessToken();
            $this->resource_owner_password_credentials_grant_type->disableRefreshTokenIssuanceWithAccessToken();
            $this->resource_owner_password_credentials_grant_type->enableRefreshTokenIssuanceWithAccessToken();
        }

        return $this->resource_owner_password_credentials_grant_type;
    }

    /**
     * @return null|\OAuth2\Scope\ScopeManager
     */
    private $scope_manager = null;

    /**
     * @return \OAuth2\Scope\ScopeManager
     */
    protected function getScopeManager()
    {
        if (null === $this->scope_manager) {
            $this->scope_manager = new ScopeManager(
                $this->getExceptionManager()
            );
            $this->scope_manager->addScopePolicy(new DefaultScopePolicy(['scope1', 'scope2']), true);
            $this->scope_manager->addScopePolicy(new ErrorScopePolicy($this->getExceptionManager()));
        }

        return $this->scope_manager;
    }

    /**
     * @return null|\OAuth2\Token\JWTAccessTokenManager
     */
    private $jwt_access_token_manager = null;

    /**
     * @return \OAuth2\Token\JWTAccessTokenManager
     */
    protected function getJWTAccessTokenManager()
    {
        if (null === $this->jwt_access_token_manager) {
            $this->jwt_access_token_manager = new JWTAccessTokenManager(
                $this->getJWTCreator(),
                $this->getJWTLoader(),
                'HS512',
                new JWK([
                    'kid' => 'JWK2',
                    'use' => 'sig',
                    'kty' => 'oct',
                    'k'   => 'AyM1SysPpbyDfgZld3umj1qzKObwVMkoqQ-EstJQLr_T-1qS0gZH75aKtMN3Yj0iPS4hcgUuTwjAzZr1Z9CAow',
                ]),
                $this->getIssuer()
            );

            $this->jwt_access_token_manager->enableAccessTokenEncryption(
                'A256KW',
                'A256CBC-HS512',
                new JWK([
                    'kid' => 'JWK1',
                    'use' => 'enc',
                    'kty' => 'oct',
                    'k'   => 'ABEiM0RVZneImaq7zN3u_wABAgMEBQYHCAkKCwwNDg8',
                ])
            );
            $this->jwt_access_token_manager->addTokenUpdater(new FooBarAccessTokenUpdater());
        }

        return $this->jwt_access_token_manager;
    }

    /**
     * @return null|\OAuth2\Token\BearerToken
     */
    private $bearer_token_type = null;

    /**
     * @return \OAuth2\Token\BearerToken
     */
    protected function getBearerTokenType()
    {
        if (null === $this->bearer_token_type) {
            $this->bearer_token_type = new BearerToken();

            $this->bearer_token_type->disallowAccessTokenFromQueryString();
            $this->bearer_token_type->allowAccessTokenFromQueryString();
            $this->bearer_token_type->disallowAccessTokenFromRequestBody();
            $this->bearer_token_type->allowAccessTokenFromRequestBody();
        }

        return $this->bearer_token_type;
    }

    /**
     * @return null|\OAuth2\Token\MacToken
     */
    private $mac_token_type = null;

    /**
     * @return \OAuth2\Token\MacToken
     */
    protected function getMacTokenType()
    {
        if (null === $this->mac_token_type) {
            $this->mac_token_type = new MacToken();

            $this->mac_token_type->setMacKeyMinLength(10);
            $this->mac_token_type->setMacKeyMaxLength(20);
            $this->mac_token_type->setMacAlgorithm('hmac-sha-256');
            $this->mac_token_type->setTimestampLifetime(10);
        }

        return $this->mac_token_type;
    }

    /**
     * @return null|\OAuth2\Token\TokenTypeManagerInterface
     */
    private $token_type_manager = null;

    /**
     * @return \OAuth2\Token\TokenTypeManagerInterface
     */
    protected function getTokenTypeManager()
    {
        if (null === $this->token_type_manager) {
            $this->token_type_manager = new TokenTypeManager(
                $this->getExceptionManager()
            );

            $this->token_type_manager->addTokenType($this->getBearerTokenType(), true);
            $this->token_type_manager->addTokenType($this->getMacTokenType());
        }

        return $this->token_type_manager;
    }

    /**
     * @return null|\OAuth2\Test\Stub\RefreshTokenManager
     */
    private $refresh_token_manager = null;

    /**
     * @return \OAuth2\Test\Stub\RefreshTokenManager
     */
    protected function getRefreshTokenManager()
    {
        if (null === $this->refresh_token_manager) {
            $this->refresh_token_manager = new RefreshTokenManager();

            $this->refresh_token_manager->setRefreshTokenMinLength(10);
            $this->refresh_token_manager->setRefreshTokenMaxLength(20);
            $this->refresh_token_manager->setRefreshTokenLifetime(36000);
        }

        return $this->refresh_token_manager;
    }

    /**
     * @return \OAuth2\Test\Stub\AuthCodeManager
     */
    private $auth_code_manager = null;

    /**
     * @return \OAuth2\Test\Stub\AuthCodeManager
     */
    protected function getAuthCodeManager()
    {
        if (null === $this->auth_code_manager) {
            $this->auth_code_manager = new AuthCodeManager();

            $this->auth_code_manager->setAuthorizationCodeMinLength(10);
            $this->auth_code_manager->setAuthorizationCodeMaxLength(20);
            $this->auth_code_manager->setAuthorizationCodeLifetime(15);
        }

        return $this->auth_code_manager;
    }

    /**
     * @return null|\\OAuth2\OpenIDConnect\IdTokenManager
     */
    private $id_token_manager = null;

    /**
     * @return \OAuth2\OpenIDConnect\IdTokenManager
     */
    protected function getIdTokenManager()
    {
        if (null === $this->id_token_manager) {
            $this->id_token_manager = new IdTokenManager(
                $this->getJWTLoader(),
                $this->getJWTCreator(),
                $this->getIssuer(),
                'HS512',
                new JWK([
                    'kid' => 'JWK2',
                    'use' => 'sig',
                    'kty' => 'oct',
                    'k'   => 'AyM1SysPpbyDfgZld3umj1qzKObwVMkoqQ-EstJQLr_T-1qS0gZH75aKtMN3Yj0iPS4hcgUuTwjAzZr1Z9CAow',
                ]),
                $this->getUserInfo()
            );

            //$this->id_token_manager->enablePairwiseSubject(new HashedSubjectIdentifier($this->getPairwiseKey(), 'sha512', $this->getPairwiseAdditionalData()));
        }

        return $this->id_token_manager;
    }

    /**
     * @var null|\Jose\JWTLoader
     */
    private $jwt_loader = null;

    /**
     * @return \Jose\JWTLoader
     */
    protected function getJWTLoader()
    {
        if (null === $this->jwt_loader) {
            $this->jwt_loader = new JWTLoader(
                $this->getClaimCheckerManager(),
                Verifier::createVerifier(['HS256', 'HS512', 'RS256', 'RS512'])
            );
            $this->jwt_loader->enableEncryptionSupport(Decrypter::createDecrypter(
                ['A128KW', 'A256KW', 'A128GCMKW', 'A256GCMKW', 'PBES2-HS256+A128KW', 'PBES2-HS512+A256KW', 'RSA1_5', 'RSA-OAEP', 'RSA-OAEP-256'],
                ['A128GCM', 'A256GCM', 'A128CBC-HS256', 'A256CBC-HS512']
            ));
        }

        return $this->jwt_loader;
    }

    /**
     * @var null|\Jose\JWTCreator
     */
    private $jwt_creator = null;

    /**
     * @return \Jose\JWTCreator
     */
    protected function getJWTCreator()
    {
        if (null === $this->jwt_creator) {
            $this->jwt_creator = new JWTCreator(Signer::createSigner(
                ['HS256', 'HS512', 'RS256', 'RS512']
            ));
            $this->jwt_creator->enableEncryptionSupport(Encrypter::createEncrypter(
                ['A128KW', 'A256KW', 'A128GCMKW', 'A256GCMKW', 'PBES2-HS256+A128KW', 'PBES2-HS512+A256KW', 'RSA1_5', 'RSA-OAEP', 'RSA-OAEP-256'],
                ['A128GCM', 'A256GCM', 'A128CBC-HS256', 'A256CBC-HS512']
            ));
        }

        return $this->jwt_creator;
    }

    /**
     * @var null|\Jose\Checker\CheckerManagerInterface
     */
    private $claim_checker_manager = null;

    /**
     * @return \Jose\Checker\CheckerManagerInterface
     */
    protected function getClaimCheckerManager()
    {
        if (null === $this->claim_checker_manager) {
            $this->claim_checker_manager = CheckerManagerFactory::createClaimCheckerManager();
            $this->claim_checker_manager->addClaimChecker(new AudienceChecker($this->getIssuer()));
        }

        return $this->claim_checker_manager;
    }

    /**
     * @var null|\OAuth2\OpenIDConnect\Metadata
     */
    private $metadata = null;

    /**
     * @return \OAuth2\OpenIDConnect\Metadata
     */
    protected function getMetadata()
    {
        if (null === $this->metadata) {
            $this->metadata = new Metadata();

            $this->metadata->setIssuer($this->getIssuer());
            $this->metadata->setAuthorizationEndpoint('https://my.server.com/authorize');
            $this->metadata->setTokenEndpoint('https://my.server.com/token');
            $this->metadata->setUserinfoEndpoint('https://my.server.com/user_info');
            $this->metadata->setJwksUri('https://my.server.com/jwks');
            $this->metadata->setRegistrationEndpoint('https://my.server.com/register');
            $this->metadata->setScopesSupported($this->getScopeManager()->getAvailableScopes());
            $this->metadata->setResponseTypesSupported($this->getAuthorizationEndpoint()->getResponseTypesSupported());
            $this->metadata->setResponseModesSupported($this->getAuthorizationEndpoint()->getResponseModesSupported());
            $this->metadata->setGrantTypesSupported($this->getTokenEndpoint()->getGrantTypesSupported());
            $this->metadata->setAcrValuesSupported([]);
            $this->metadata->setSubjectTypesSupported($this->getUserInfo()->isPairwiseSubjectIdentifierSupported() ? ['public', 'pairwise'] : ['public']);
            $this->metadata->setIdTokenSigningAlgValuesSupported($this->getIdTokenManager()->getSignatureAlgorithms());
            $this->metadata->setIdTokenEncryptionAlgValuesSupported($this->getIdTokenManager()->getKeyEncryptionAlgorithms());
            $this->metadata->setIdTokenEncryptionEncValuesSupported($this->getIdTokenManager()->getContentEncryptionAlgorithms());
            $this->metadata->setUserinfoSigningAlgValuesSupported($this->getUserInfoEndpoint()->getSupportedSignatureAlgorithms());
            $this->metadata->setUserinfoEncryptionAlgValuesSupported($this->getUserInfoEndpoint()->getSupportedKeyEncryptionAlgorithms());
            $this->metadata->setUserinfoEncryptionEncValuesSupported($this->getUserInfoEndpoint()->getSupportedContentEncryptionAlgorithms());
            $this->metadata->setRequestObjectSigningAlgValuesSupported($this->getJWTLoader()->getSupportedSignatureAlgorithms());
            $this->metadata->setRequestObjectEncryptionAlgValuesSupported($this->getJWTLoader()->getSupportedKeyEncryptionAlgorithms());
            $this->metadata->setRequestObjectEncryptionEncValuesSupported($this->getJWTLoader()->getSupportedContentEncryptionAlgorithms());
            $this->metadata->setTokenEndpointAuthMethodsSupported($this->getClientManager()->getSupportedAuthenticationMethods());
            $this->metadata->setTokenEndpointAuthSigningAlgValuesSupported($this->getAuthorizationFactory()->getSupportedSignatureAlgorithms());
            $this->metadata->setTokenEndpointAuthEncryptionAlgValuesSupported($this->getJWTLoader()->getSupportedKeyEncryptionAlgorithms());
            $this->metadata->setTokenEndpointAuthEncryptionEncValuesSupported($this->getJWTLoader()->getSupportedContentEncryptionAlgorithms());
            $this->metadata->setDisplayValuesSupported(['page']);
            $this->metadata->setClaimTypesSupported(false);
            $this->metadata->setClaimsSupported(false);
            $this->metadata->setServiceDocumentation('https://my.server.com/documentation');
            $this->metadata->setClaimsLocalesSupported([]);
            $this->metadata->setUiLocalesSupported(['en_US', 'fr_FR']);
            $this->metadata->setClaimsParameterSupported(false);
            $this->metadata->setRequestParameterSupported($this->getAuthorizationFactory()->isRequestObjectSupportEnabled());
            $this->metadata->setRequestUriParameterSupported($this->getAuthorizationFactory()->isRequestObjectReferenceSupportEnabled());
            $this->metadata->setRequireRequestUriRegistration(true);
            $this->metadata->setOpPolicyUri('https://my.server.com/policy.html');
            $this->metadata->setOpTosUri('https://my.server.com/tos.html');
        }

        return $this->metadata;
    }

    /**
     * @return \OAuth2\Endpoint\TokenType\AccessToken
     */
    protected function getAccessTokenType()
    {
        $access_token_type = new AccessToken(
            $this->getJWTAccessTokenManager(),
            $this->getRefreshTokenManager()
        );

        $access_token_type->enableRefreshTokensRevocationWithAccessTokens();
        $access_token_type->disableRefreshTokensRevocationWithAccessTokens();
        $access_token_type->enableRefreshTokensRevocationWithAccessTokens();

        return $access_token_type;
    }

    /**
     * @return \OAuth2\Endpoint\TokenType\RefreshToken
     */
    protected function getRefreshTokenType()
    {
        return new RefreshToken($this->getRefreshTokenManager());
    }
}
