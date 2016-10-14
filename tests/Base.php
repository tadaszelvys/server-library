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
use Jose\JWTCreator;
use Jose\JWTLoader;
use Jose\Object\JWKSet;
use Jose\Signer;
use Jose\Verifier;
use OAuth2\Endpoint\Authorization\AuthorizationFactory;
use OAuth2\Endpoint\Authorization\AuthorizationRequestLoader;
use OAuth2\Endpoint\Authorization\ParameterChecker\DisplayParameterChecker;
use OAuth2\Endpoint\Authorization\ParameterChecker\NonceParameterChecker;
use OAuth2\Endpoint\Authorization\ParameterChecker\ParameterCheckerManager;
use OAuth2\Endpoint\Authorization\ParameterChecker\PromptParameterChecker;
use OAuth2\Endpoint\Authorization\ParameterChecker\RedirectUriParameterChecker;
use OAuth2\Endpoint\Authorization\ParameterChecker\ResponseModeParameterChecker;
use OAuth2\Endpoint\Authorization\ParameterChecker\ResponseTypeParameterChecker;
use OAuth2\Endpoint\Authorization\ParameterChecker\ScopeParameterChecker;
use OAuth2\Endpoint\Authorization\ParameterChecker\StateParameterChecker;
use OAuth2\Endpoint\ClientRegistration\ClientRegistrationEndpoint;
use OAuth2\Client\Rule\CommonParametersRule;
use OAuth2\Client\Rule\GrantTypeFlowRule;
use OAuth2\Client\Rule\IdTokenAlgorithmsRule;
use OAuth2\Client\Rule\RedirectionUriRule;
use OAuth2\Client\Rule\RequestUriRule;
use OAuth2\Client\Rule\ResourceServerRule;
use OAuth2\Client\Rule\ScopeRule;
use OAuth2\Client\Rule\SectorIdentifierUriRule;
use OAuth2\Client\Rule\SoftwareRule;
use OAuth2\Client\Rule\SubjectTypeRule;
use OAuth2\Client\Rule\TokenEndpointAuthMethodEndpointRule;
use OAuth2\Endpoint\Token\TokenEndpoint;
use OAuth2\Endpoint\TokenIntrospection\TokenIntrospectionEndpoint;
use OAuth2\Endpoint\TokenRevocation\TokenRevocationEndpoint;
use OAuth2\Endpoint\TokenType\AccessToken;
use OAuth2\Endpoint\TokenType\AuthCode;
use OAuth2\Endpoint\TokenType\RefreshToken;
use OAuth2\Exception\ExceptionManager;
use OAuth2\Grant\AuthorizationCodeGrantType;
use OAuth2\Grant\ClientCredentialsGrantType;
use OAuth2\Grant\GrantTypeManager;
use OAuth2\Grant\ImplicitGrantType;
use OAuth2\Grant\JWTBearerGrantType;
use OAuth2\Grant\PKCEMethod\PKCEMethodManager;
use OAuth2\Grant\PKCEMethod\Plain;
use OAuth2\Grant\PKCEMethod\S256;
use OAuth2\Grant\RefreshTokenGrantType;
use OAuth2\Grant\ResourceOwnerPasswordCredentialsGrantType;
use OAuth2\Grant\ResponseTypeManager;
use OAuth2\OpenIdConnect\ClaimSource\ClaimSourceManager;
use OAuth2\OpenIdConnect\IdTokenGrantType;
use OAuth2\OpenIdConnect\IdTokenManager;
use OAuth2\OpenIdConnect\IssuerDiscoveryEndpoint;
use OAuth2\OpenIdConnect\Metadata;
use OAuth2\OpenIdConnect\NoneResponseType;
use OAuth2\OpenIdConnect\OpenIdConnectTokenEndpointExtension;
use OAuth2\OpenIdConnect\Pairwise\EncryptedSubjectIdentifier;
use OAuth2\OpenIdConnect\SessionManagement\IFrameEndpoint;
use OAuth2\OpenIdConnect\UserInfo\ScopeSupport\AddressScopeSupport;
use OAuth2\OpenIdConnect\UserInfo\ScopeSupport\EmailScopeSupport;
use OAuth2\OpenIdConnect\UserInfo\ScopeSupport\PhoneScopeSupport;
use OAuth2\OpenIdConnect\UserInfo\ScopeSupport\ProfilScopeSupport;
use OAuth2\OpenIdConnect\UserInfo\ScopeSupport\UserInfoScopeSupportManager;
use OAuth2\OpenIdConnect\UserInfo\UserInfo;
use OAuth2\OpenIdConnect\UserInfo\UserInfoEndpoint;
use OAuth2\ResponseMode\FormPostResponseMode;
use OAuth2\ResponseMode\FragmentResponseMode;
use OAuth2\ResponseMode\QueryResponseMode;
use OAuth2\ResponseMode\ResponseModeManager;
use OAuth2\Scope\DefaultScopePolicy;
use OAuth2\Scope\ErrorScopePolicy;
use OAuth2\Security\EntryPoint;
use OAuth2\Security\Handler\AccessTokenHandler;
use OAuth2\Security\Listener;
use OAuth2\Test\Stub\AuthCodeManager;
use OAuth2\Test\Stub\AuthorizationEndpoint;
use OAuth2\Test\Stub\ClientManager;
use OAuth2\Test\Stub\DistributedClaimSource;
use OAuth2\Test\Stub\FooBarAccessTokenUpdater;
use OAuth2\Test\Stub\JWTAccessTokenManager;
use OAuth2\Test\Stub\NoneListener;
use OAuth2\Test\Stub\PreConfiguredAuthorizationManager;
use OAuth2\Test\Stub\RefreshTokenManager;
use OAuth2\Test\Stub\ScopeManager;
use OAuth2\Test\Stub\SessionStateParameterExtension;
use OAuth2\Test\Stub\TooManyRequestsExceptionFactory;
use OAuth2\Test\Stub\UriExtension;
use OAuth2\Test\Stub\UserAccountManager;
use OAuth2\Token\BearerToken;
use OAuth2\Token\MacToken;
use OAuth2\Token\TokenTypeManager;
use OAuth2\Test\Stub\ClientAssertionJwt;
use OAuth2\Test\Stub\ClientSecretBasic;
use OAuth2\Test\Stub\ClientSecretPost;
use OAuth2\Test\Stub\ClientRegistrationManagementRule;
use OAuth2\TokenEndpointAuthMethod\None;
use OAuth2\TokenEndpointAuthMethod\TokenEndpointAuthMethodManager;
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
     * @var \OAuth2\Endpoint\Authorization\AuthorizationFactoryInterface
     */
    private $authorization_factory;

    /**
     * @return \OAuth2\Endpoint\Authorization\AuthorizationFactoryInterface
     */
    protected function getAuthorizationFactory()
    {
        if (null === $this->authorization_factory) {
            $this->authorization_factory = new AuthorizationFactory(
                $this->getAuthorizationRequestLoader(),
                $this->getResponseTypeManager(),
                $this->getResponseModeManager(),
                $this->getParameterCheckerManager(),
                $this->getExceptionManager()
            );
        }

        return $this->authorization_factory;
    }

    /**
     * @var null|\OAuth2\Endpoint\Authorization\ParameterChecker\ParameterCheckerManagerInterface
     */
    private $parameter_checker_manager = null;

    /**
     * @return \OAuth2\Endpoint\Authorization\ParameterChecker\ParameterCheckerManagerInterface
     */
    protected function getParameterCheckerManager()
    {
        if (null === $this->parameter_checker_manager) {
            $this->parameter_checker_manager = new ParameterCheckerManager($this->getExceptionManager());

            $scope_checker = new ScopeParameterChecker();
            $scope_checker->enableScopeSupport($this->getScopeManager());

            $this->parameter_checker_manager->addParameterChecker(new DisplayParameterChecker());
            $this->parameter_checker_manager->addParameterChecker(new PromptParameterChecker());
            $this->parameter_checker_manager->addParameterChecker(new ResponseTypeParameterChecker());
            $this->parameter_checker_manager->addParameterChecker(new StateParameterChecker(true));
            $this->parameter_checker_manager->addParameterChecker($scope_checker);
            $this->parameter_checker_manager->addParameterChecker(new RedirectUriParameterChecker(false, false));
            $this->parameter_checker_manager->addParameterChecker(new ResponseModeParameterChecker(true));
            $this->parameter_checker_manager->addParameterChecker(new NonceParameterChecker());
        }

        return $this->parameter_checker_manager;
    }

    /**
     * @var null|\OAuth2\Grant\ResponseTypeManagerInterface
     */
    private $response_type_manager;

    /**
     * @return \OAuth2\Grant\ResponseTypeManagerInterface
     */
    protected function getResponseTypeManager()
    {
        if (null === $this->response_type_manager) {
            $this->response_type_manager = new ResponseTypeManager();

            $this->response_type_manager->addResponseType($this->getAuthorizationCodeGrantType());
            $this->response_type_manager->addResponseType($this->getImplicitGrantType());
            $this->response_type_manager->addResponseType($this->getNoneResponseType());
            $this->response_type_manager->addResponseType($this->getIdTokenGrantType());
        }

        return $this->response_type_manager;
    }

    /**
     * @var null|\OAuth2\ResponseMode\ResponseModeManagerInterface
     */
    private $response_mode_manager;

    /**
     * @return \OAuth2\ResponseMode\ResponseModeManagerInterface
     */
    protected function getResponseModeManager()
    {
        if (null === $this->response_mode_manager) {
            $this->response_mode_manager = new ResponseModeManager();

            $this->response_mode_manager->addResponseMode(new QueryResponseMode());
            $this->response_mode_manager->addResponseMode(new FragmentResponseMode());
            $this->response_mode_manager->addResponseMode(new FormPostResponseMode());
        }

        return $this->response_mode_manager;
    }

    /**
     * @var \OAuth2\Endpoint\Authorization\AuthorizationRequestLoaderInterface
     */
    private $authorization_request_loader;

    /**
     * @return \OAuth2\Endpoint\Authorization\AuthorizationRequestLoaderInterface
     */
    protected function getAuthorizationRequestLoader()
    {
        if (null === $this->authorization_request_loader) {
            $this->authorization_request_loader = new AuthorizationRequestLoader(
                $this->getClientManager(),
                $this->getExceptionManager()
            );

            $this->authorization_request_loader->enableRequestObjectSupport(
                $this->getJWTLoader()
            );
            $this->authorization_request_loader->enableRequestObjectReferenceSupport();

            $this->authorization_request_loader->enableEncryptedRequestObjectSupport(
                new JWKSet(['keys' => [
                    [
                        'kid' => 'JWK1',
                        'use' => 'enc',
                        'kty' => 'oct',
                        'k'   => 'ABEiM0RVZneImaq7zN3u_wABAgMEBQYHCAkKCwwNDg8',
                    ],
                ]]),
                false
            );

            $this->authorization_request_loader->enableRequestUriRegistrationRequirement();
            $this->authorization_request_loader->disableRequestUriRegistrationRequirement();
            $this->authorization_request_loader->disallowUnsecuredConnections();
            $this->authorization_request_loader->allowUnsecuredConnections(); // We allow unsecured connections because we send request against the local server for all tests. Should not be used in production.

            $this->assertTrue($this->authorization_request_loader->isEncryptedRequestsSupportEnabled());
            $this->assertEquals(['HS256', 'HS512', 'RS256', 'RS512'], $this->authorization_request_loader->getSupportedSignatureAlgorithms());
            $this->assertEquals(['A128KW', 'A256KW', 'A128GCMKW', 'A256GCMKW', 'PBES2-HS256+A128KW', 'PBES2-HS512+A256KW', 'RSA1_5', 'RSA-OAEP', 'RSA-OAEP-256'], $this->authorization_request_loader->getSupportedKeyEncryptionAlgorithms());
            $this->assertEquals(['A128GCM', 'A256GCM', 'A128CBC-HS256', 'A256CBC-HS512'], $this->authorization_request_loader->getSupportedContentEncryptionAlgorithms());
        }

        return $this->authorization_request_loader;
    }

    /**
     * @var null|\OAuth2\Endpoint\TokenRevocation\TokenRevocationEndpointInterface
     */
    private $revocation_endpoint = null;

    /**
     * @return \OAuth2\Endpoint\TokenRevocation\TokenRevocationEndpointInterface
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
            $this->revocation_endpoint->addRevocationTokenType($this->getAuthCodeType());
        }

        return $this->revocation_endpoint;
    }

    /**
     * @var null|\OAuth2\OpenIdConnect\UserInfo\UserInfoInterface
     */
    private $userinfo = null;

    /**
     * @return \OAuth2\OpenIdConnect\UserInfo\UserInfoInterface
     */
    protected function getUserInfo()
    {
        if (null === $this->userinfo) {
            $this->userinfo = new UserInfo(
                $this->getUserInfoScopeSupportManager(),
                $this->getClaimSourceManager(),
                $this->getExceptionManager()
            );

            $this->userinfo->enablePairwiseSubject(new EncryptedSubjectIdentifier($this->getPairwiseKey(), 'aes-128-cbc', $this->getPairwiseAdditionalData(), $this->getPairwiseAdditionalData()));
            $this->userinfo->setPublicSubjectByDefault();
            $this->userinfo->setPairwiseSubjectByDefault();
            $this->assertTrue($this->userinfo->isPairwiseSubjectDefault());
        }

        return $this->userinfo;
    }

    /**
     * @var null|\OAuth2\OpenIdConnect\UserInfo\ScopeSupport\UserInfoScopeSupportManagerInterface
     */
    private $userinfo_scope_support_manager = null;

    /**
     * @return \OAuth2\OpenIdConnect\UserInfo\ScopeSupport\UserInfoScopeSupportManagerInterface
     */
    protected function getUserInfoScopeSupportManager()
    {
        if (null === $this->userinfo_scope_support_manager) {
            $this->userinfo_scope_support_manager = new UserInfoScopeSupportManager();

            $this->userinfo_scope_support_manager->addUserInfoScopeSupport(new ProfilScopeSupport());
            $this->userinfo_scope_support_manager->addUserInfoScopeSupport(new AddressScopeSupport());
            $this->userinfo_scope_support_manager->addUserInfoScopeSupport(new EmailScopeSupport());
            $this->userinfo_scope_support_manager->addUserInfoScopeSupport(new PhoneScopeSupport());
        }

        return $this->userinfo_scope_support_manager;
    }

    /**
     * @var null|\OAuth2\OpenIdConnect\IssuerDiscoveryEndpointInterface
     */
    private $issuer_discovery_endpoint = null;

    /**
     * @return \OAuth2\OpenIdConnect\IssuerDiscoveryEndpointInterface
     */
    protected function getIssuerDiscoveryEndpoint()
    {
        if (null === $this->issuer_discovery_endpoint) {
            $this->issuer_discovery_endpoint = new IssuerDiscoveryEndpoint(
                $this->getUserAccountManager(),
                $this->getExceptionManager(),
                $this->getIssuer(),
                'https://my-service.com:9000'
            );
        }

        return $this->issuer_discovery_endpoint;
    }

    /**
     * @var null|\OAuth2\OpenIdConnect\UserInfo\UserInfoEndpointInterface
     */
    private $userinfo_endpoint = null;

    /**
     * @return \OAuth2\OpenIdConnect\UserInfo\UserInfoEndpointInterface
     */
    protected function getUserInfoEndpoint()
    {
        if (null === $this->userinfo_endpoint) {
            $this->userinfo_endpoint = new UserInfoEndpoint(
                $this->getUserAccountManager(),
                $this->getClientManager(),
                $this->getUserInfo(),
                $this->getExceptionManager()
            );

            $this->userinfo_endpoint->enableSignedResponsesSupport(
                $this->getJWTCreator(),
                $this->getIssuer(),
                'HS512',
                $this->getSignatureKeySet()
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
                new AccessTokenHandler($this->getJWTAccessTokenManager()),
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
     * @var null|\OAuth2\Endpoint\TokenIntrospection\TokenIntrospectionEndpoint
     */
    private $token_introspection_endpoint = null;

    /**
     * @return \OAuth2\Endpoint\TokenIntrospection\TokenIntrospectionEndpoint
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
            $this->token_introspection_endpoint->addIntrospectionTokenType($this->getAuthCodeType());
        }

        return $this->token_introspection_endpoint;
    }

    /**
     * @var null|\OAuth2\Endpoint\Token\TokenEndpoint
     */
    private $token_endpoint = null;

    /**
     * @return \OAuth2\Endpoint\Token\TokenEndpoint
     */
    protected function getTokenEndpoint()
    {
        if (null === $this->token_endpoint) {
            $this->token_endpoint = new TokenEndpoint(
                $this->getGrantTypeManager(),
                $this->getTokenTypeManager(),
                $this->getJWTAccessTokenManager(),
                $this->getClientManager(),
                $this->getUserAccountManager(),
                $this->getExceptionManager(),
                $this->getRefreshTokenManager()
            );

            $this->token_endpoint->enableScopeSupport($this->getScopeManager());
            $this->token_endpoint->addTokenEndpointExtension($this->getOpenIdConnectTokenEndpointExtension());
            $this->token_endpoint->allowAccessTokenTypeParameter();
        }

        return $this->token_endpoint;
    }

    /**
     * @var null|\OAuth2\OpenIdConnect\OpenIdConnectTokenEndpointExtension
     */
    private $openid_connect_token_endpoint_extension = null;

    /**
     * @return \OAuth2\OpenIdConnect\OpenIdConnectTokenEndpointExtension
     */
    protected function getOpenIdConnectTokenEndpointExtension()
    {
        if (null === $this->openid_connect_token_endpoint_extension) {
            $this->openid_connect_token_endpoint_extension = new OpenIdConnectTokenEndpointExtension(
                $this->getIdTokenManager(),
                $this->getUserAccountManager()
            );
        }

        return $this->openid_connect_token_endpoint_extension;
    }

    /**
     * @var null|\OAuth2\Grant\GrantTypeManagerInterface
     */
    private $grant_type_manager = null;

    /**
     * @return \OAuth2\Grant\GrantTypeManagerInterface
     */
    protected function getGrantTypeManager()
    {
        if (null === $this->grant_type_manager) {
            $this->grant_type_manager = new GrantTypeManager();

            $this->grant_type_manager->addGrantType($this->getAuthorizationCodeGrantType());
            $this->grant_type_manager->addGrantType($this->getAuthorizationCodeGrantType());
            $this->grant_type_manager->addGrantType($this->getClientCredentialsGrantType());
            $this->grant_type_manager->addGrantType($this->getRefreshTokenGrantType());
            $this->grant_type_manager->addGrantType($this->getResourceOwnerPasswordCredentialsGrantType());
            $this->grant_type_manager->addGrantType($this->getJWTBearerGrantType());
        }

        return $this->grant_type_manager;
    }

    /**
     * @var null|\OAuth2\Test\Stub\AuthorizationEndpoint
     */
    private $authorization_endpoint = null;

    /**
     * @return \OAuth2\Test\Stub\AuthorizationEndpoint
     */
    protected function getAuthorizationEndpoint()
    {
        if (null === $this->authorization_endpoint) {
            $this->authorization_endpoint = new AuthorizationEndpoint(
                $this->getUserAccountManager(),
                $this->getAuthorizationFactory(),
                $this->getExceptionManager()
            );

            $this->authorization_endpoint->enableIdTokenSupport($this->getIdTokenManager());
            $this->authorization_endpoint->enablePreConfiguredAuthorizationSupport($this->getPreConfiguredAuthorizationManager());

            $this->authorization_endpoint->addExtension(new SessionStateParameterExtension('oauth2_session_state'));
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
            $this->exception_manager->addExceptionFactory(new TooManyRequestsExceptionFactory());
        }

        return $this->exception_manager;
    }

    /**
     * @var null|\OAuth2\Test\Stub\UserAccountManager
     */
    private $user_manager = null;

    /**
     * @return \OAuth2\Test\Stub\UserAccountManager
     */
    protected function getUserAccountManager()
    {
        if (null === $this->user_manager) {
            $this->user_manager = new UserAccountManager();
        }

        return $this->user_manager;
    }

    /**
     * @var null|\OAuth2\TokenEndpointAuthMethod\ClientAssertionJwt
     */
    private $assertion_jwt_auth_method = null;

    /**
     * @return \OAuth2\TokenEndpointAuthMethod\ClientAssertionJwt
     */
    protected function getAssertionJwtAuthMethod()
    {
        if (null == $this->assertion_jwt_auth_method) {
            $this->assertion_jwt_auth_method = new ClientAssertionJwt($this->getJWTLoader(), $this->getExceptionManager(), 3600);
            $this->assertEquals(['HS256', 'HS512', 'RS256', 'RS512'], $this->assertion_jwt_auth_method->getSupportedSignatureAlgorithms());
            $this->assertEquals(['A128KW', 'A256KW', 'A128GCMKW', 'A256GCMKW', 'PBES2-HS256+A128KW', 'PBES2-HS512+A256KW', 'RSA1_5', 'RSA-OAEP', 'RSA-OAEP-256',], $this->assertion_jwt_auth_method->getSupportedKeyEncryptionAlgorithms());
            $this->assertEquals(['A128GCM', 'A256GCM', 'A128CBC-HS256', 'A256CBC-HS512',], $this->assertion_jwt_auth_method->getSupportedContentEncryptionAlgorithms());
        }

        return $this->assertion_jwt_auth_method;
    }

    /**
     * @var null|\OAuth2\TokenEndpointAuthMethod\TokenEndpointAuthMethodManager
     */
    private $token_endpoint_auth_method_manager = null;

    /**
     * @return \OAuth2\TokenEndpointAuthMethod\TokenEndpointAuthMethodManager
     */
    protected function getTokenEndpointAuthMethodManager()
    {
        if (null == $this->token_endpoint_auth_method_manager) {
            $this->token_endpoint_auth_method_manager = new TokenEndpointAuthMethodManager();

            $jwt_assertion = $this->getAssertionJwtAuthMethod();
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

            $this->token_endpoint_auth_method_manager->addTokenEndpointAuthMethod(new None());
            $this->token_endpoint_auth_method_manager->addTokenEndpointAuthMethod(new ClientSecretBasic($this->realm, 3600));
            $this->token_endpoint_auth_method_manager->addTokenEndpointAuthMethod(new ClientSecretPost(3600));
            $this->token_endpoint_auth_method_manager->addTokenEndpointAuthMethod($jwt_assertion);
        }

        return $this->token_endpoint_auth_method_manager;
    }

    /**
     * @var null|\OAuth2\Test\Stub\ClientManager
     */
    private $client_manager = null;

    /**
     * @return \OAuth2\Test\Stub\ClientManager
     */
    protected function getClientManager()
    {
        if (null === $this->client_manager) {
            $this->client_manager = new ClientManager(
                $this->getTokenEndpointAuthMethodManager(),
                $this->getExceptionManager()
            );
            $this->client_manager->addRule(new GrantTypeFlowRule(
                $this->getGrantTypeManager(),
                $this->getResponseTypeManager()
            ));

            $scope_rule = new ScopeRule();
            $scope_rule->enableScopeSupport($this->getScopeManager());

            $this->client_manager->addRule(new RedirectionUriRule());
            $this->client_manager->addRule(new RequestUriRule());
            $this->client_manager->addRule($scope_rule);

            $sector_identifier_uri_rule = new SectorIdentifierUriRule();
            $sector_identifier_uri_rule->disallowHttpConnections();
            $sector_identifier_uri_rule->allowHttpConnections(); // We allow http connections
            $sector_identifier_uri_rule->disallowUnsecuredConnections();
            $sector_identifier_uri_rule->allowUnsecuredConnections(); // We allow unsecured connections because we send request against the local server for all tests. Should not be used in production.
            $this->client_manager->addRule($sector_identifier_uri_rule);
            $this->client_manager->addRule(new TokenEndpointAuthMethodEndpointRule(
                $this->getTokenEndpointAuthMethodManager()
            ));
            $this->client_manager->addRule(new IdTokenAlgorithmsRule($this->getIdTokenManager()));
            $this->client_manager->addRule(new SubjectTypeRule($this->getUserInfo()));
            $this->client_manager->addRule(new ResourceServerRule());
            $this->client_manager->addRule(new CommonParametersRule());
            $this->client_manager->addRule(new SoftwareRule());
            $this->client_manager->addRule(new ClientRegistrationManagementRule());
        }

        return $this->client_manager;
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
                $this->getPKCEMethodManager()
            );

            $this->authorization_code_grant_type->enableScopeSupport($this->getScopeManager());
            $this->authorization_code_grant_type->enablePKCEForPublicClientsEnforcement();
            $this->authorization_code_grant_type->disablePKCEForPublicClientsEnforcement();
            $this->authorization_code_grant_type->enablePKCEForPublicClientsEnforcement();
            $this->authorization_code_grant_type->disallowPublicClients();
            $this->authorization_code_grant_type->allowPublicClients();
        }

        return $this->authorization_code_grant_type;
    }

    /**
     * @var null|\OAuth2\Grant\PKCEMethod\PKCEMethodManagerInterface
     */
    private $pkce_method_manager = null;

    /**
     * @return \OAuth2\Grant\PKCEMethod\PKCEMethodManagerInterface
     */
    protected function getPKCEMethodManager()
    {
        if (null === $this->pkce_method_manager) {
            $this->pkce_method_manager = new PKCEMethodManager();

            $this->pkce_method_manager->addPKCEMethod(new Plain());
            $this->pkce_method_manager->addPKCEMethod(new S256());
        }

        return $this->pkce_method_manager;
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
     * @var null|\OAuth2\OpenIdConnect\NoneResponseType
     */
    private $none_response_type = null;

    /**
     * @return \OAuth2\OpenIdConnect\NoneResponseType
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
     * @var null|\OAuth2\OpenIdConnect\IdTokenGrantType
     */
    private $id_token_type = null;

    /**
     * @return \OAuth2\OpenIdConnect\IdTokenGrantType
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
                $this->getJWTAccessTokenManager(),
                $this->getExceptionManager()
            );
            $this->implicit_grant_type->allowAccessTokenTypeParameter();
            $this->implicit_grant_type->disallowAccessTokenTypeParameter();
            $this->implicit_grant_type->disallowConfidentialClients();
            $this->implicit_grant_type->allowConfidentialClients();
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
                $this->getUserAccountManager(),
                $this->getExceptionManager()
            );
            $this->resource_owner_password_credentials_grant_type->disallowRefreshTokenIssuance();
            $this->assertFalse($this->resource_owner_password_credentials_grant_type->isRefreshTokenIssuanceAllowed());
            $this->resource_owner_password_credentials_grant_type->allowRefreshTokenIssuance();
            $this->assertTrue($this->resource_owner_password_credentials_grant_type->isRefreshTokenIssuanceAllowed());

            $this->resource_owner_password_credentials_grant_type->allowRefreshTokenIssuanceForPublicClients();
            $this->assertTrue($this->resource_owner_password_credentials_grant_type->isRefreshTokenIssuanceForPublicClientsAllowed());
            $this->resource_owner_password_credentials_grant_type->disallowRefreshTokenIssuanceForPublicClients();
            $this->assertFalse($this->resource_owner_password_credentials_grant_type->isRefreshTokenIssuanceForPublicClientsAllowed());
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
                $this->getClientManager(),
                $this->getJWTCreator(),
                $this->getJWTLoader(),
                'HS512',
                $this->getSignatureKeySet(),
                'A256KW',
                'A256CBC-HS512',
                $this->getEncryptionKeySet(),
                $this->getIssuer()
            );

            $this->jwt_access_token_manager->setAccessTokenLifetime(1000);
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

            $this->bearer_token_type->disallowTokenFromQueryString();
            $this->bearer_token_type->allowTokenFromQueryString();
            $this->bearer_token_type->disallowTokenFromRequestBody();
            $this->bearer_token_type->allowTokenFromRequestBody();

            $this->bearer_token_type->disallowTokenFromAuthorizationHeader();
            $this->bearer_token_type->allowTokenFromAuthorizationHeader();
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
            $this->refresh_token_manager = new RefreshTokenManager($this->getClientManager());

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
            $this->auth_code_manager = new AuthCodeManager($this->getClientManager());

            $this->auth_code_manager->setAuthorizationCodeMinLength(10);
            $this->auth_code_manager->setAuthorizationCodeMaxLength(20);
            $this->auth_code_manager->setAuthorizationCodeLifetime(15);
        }

        return $this->auth_code_manager;
    }

    /**
     * @return null|\\OAuth2\OpenIdConnect\IdTokenManager
     */
    private $id_token_manager = null;

    /**
     * @return \OAuth2\OpenIdConnect\IdTokenManager
     */
    protected function getIdTokenManager()
    {
        if (null === $this->id_token_manager) {
            $this->id_token_manager = new IdTokenManager(
                $this->getJWTCreator(),
                $this->getJWTLoader(),
                $this->getIssuer(),
                'HS512',
                $this->getSignatureKeySet(),
                $this->getEncryptionKeySet(),
                $this->getUserInfo()
            );
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
            $this->jwt_loader->enableDecryptionSupport(Decrypter::createDecrypter(
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
     * @var null|\OAuth2\OpenIdConnect\ClaimSource\ClaimSourceManagerInterface
     */
    private $claim_source_manager = null;

    /**
     * @return \OAuth2\OpenIdConnect\ClaimSource\ClaimSourceManagerInterface
     */
    protected function getClaimSourceManager()
    {
        if (null === $this->claim_source_manager) {
            $this->claim_source_manager = new ClaimSourceManager();
            $this->claim_source_manager->addClaimSource(new DistributedClaimSource());
        }

        return $this->claim_source_manager;
    }

    /**
     * @var null|\OAuth2\OpenIdConnect\ClaimSource\ClaimSourceManagerInterface|\OAuth2\Test\Stub\PreConfiguredAuthorizationManager
     */
    private $pre_configured_authorization_manager = null;

    /**
     * @return \OAuth2\OpenIdConnect\ClaimSource\ClaimSourceManagerInterface|\OAuth2\Test\Stub\PreConfiguredAuthorizationManager
     */
    protected function getPreConfiguredAuthorizationManager()
    {
        if (null === $this->pre_configured_authorization_manager) {
            $this->pre_configured_authorization_manager = new PreConfiguredAuthorizationManager($this->getClientManager());
        }

        return $this->pre_configured_authorization_manager;
    }

    /**
     * @var null|\OAuth2\Endpoint\ClientRegistration\ClientRegistrationEndpointInterface
     */
    private $client_registration_endpoint = null;

    /**
     * @return \OAuth2\Endpoint\ClientRegistration\ClientRegistrationEndpointInterface
     */
    protected function getClientRegistrationEndpoint()
    {
        if (null === $this->client_registration_endpoint) {
            $this->client_registration_endpoint = new ClientRegistrationEndpoint(
                $this->getClientManager(),
                $this->getExceptionManager()
            );
            $this->client_registration_endpoint->enableSoftwareStatementSupport(
                $this->getJWTLoader(),
                $this->getSignatureKeySet()
            );
        }

        return $this->client_registration_endpoint;
    }

    protected function enableSoftwareStatementSupport()
    {
        $client_registration_endpoint = $this->getClientRegistrationEndpoint();
        $client_registration_endpoint->enableSoftwareStatementSupport(
            $this->getJWTLoader(),
            $this->getSignatureKeySet()
        );
    }

    /**
     * @var null|\OAuth2\OpenIdConnect\Metadata
     */
    private $i_frame_endpoint = null;

    /**
     * @return \OAuth2\OpenIdConnect\SessionManagement\IFrameEndpointInterface
     */
    protected function getIFrameEndpointInterface()
    {
        if (null === $this->i_frame_endpoint) {
            $this->i_frame_endpoint = new IFrameEndpoint();
        }

        return $this->i_frame_endpoint;
    }

    /**
     * @var null|\OAuth2\OpenIdConnect\SessionManagement\IFrameEndpointInterface
     */
    private $metadata = null;

    /**
     * @return \OAuth2\OpenIdConnect\Metadata
     */
    protected function getMetadata()
    {
        if (null === $this->metadata) {
            $this->metadata = new Metadata();

            $this->metadata->set('issuer', $this->getIssuer());
            $this->metadata->set('authorization_endpoint', 'https://my.server.com/authorize');
            $this->metadata->set('token_endpoint', 'https://my.server.com/token');
            $this->metadata->set('userinfo_endpoint', 'https://my.server.com/user_info');
            $this->metadata->set('jwks_uri', 'https://my.server.com/jwks');
            $this->metadata->set('registration_endpoint', 'https://my.server.com/register');
            $this->metadata->set('scopes_supported', $this->getScopeManager()->getSupportedScopes());
            $this->metadata->set('response_types_supported', $this->getResponseTypeManager()->getSupportedResponseTypes());
            if ($this->getAuthorizationFactory()->isResponseModeParameterSupported()) {
                $this->metadata->set('response_modes_supported', $this->getResponseModeManager()->getSupportedResponseModes());
            }
            $this->metadata->set('grant_types_supported', $this->getGrantTypeManager()->getSupportedGrantTypes());
            $this->metadata->set('acr_values_supported', []);
            $this->metadata->set('subject_types_supported', $this->getUserInfo()->isPairwiseSubjectIdentifierSupported() ? ['public', 'pairwise'] : ['public']);
            $this->metadata->set('id_token_signing_alg_values_supported', $this->getIdTokenManager()->getSupportedSignatureAlgorithms());
            $this->metadata->set('id_token_encryption_alg_values_supported', $this->getIdTokenManager()->getSupportedKeyEncryptionAlgorithms());
            $this->metadata->set('id_token_encryption_enc_values_supported', $this->getIdTokenManager()->getSupportedContentEncryptionAlgorithms());
            $this->metadata->set('userinfo_signing_alg_values_supported', $this->getUserInfoEndpoint()->getSupportedSignatureAlgorithms());
            $this->metadata->set('userinfo_encryption_alg_values_supported', $this->getUserInfoEndpoint()->getSupportedKeyEncryptionAlgorithms());
            $this->metadata->set('userinfo_encryption_enc_values_supported', $this->getUserInfoEndpoint()->getSupportedContentEncryptionAlgorithms());
            $this->metadata->set('request_object_signing_alg_values_supported', $this->getJWTLoader()->getSupportedSignatureAlgorithms());
            $this->metadata->set('request_object_encryption_alg_values_supported', $this->getJWTLoader()->getSupportedKeyEncryptionAlgorithms());
            $this->metadata->set('request_object_encryption_enc_values_supported', $this->getJWTLoader()->getSupportedContentEncryptionAlgorithms());
            $this->metadata->set('token_endpoint_auth_methods_supported', $this->getTokenEndpointAuthMethodManager()->getSupportedTokenEndpointAuthMethods());
            $this->metadata->set('token_endpoint_auth_signing_alg_values_supported', $this->getAuthorizationRequestLoader()->getSupportedSignatureAlgorithms());
            $this->metadata->set('token_endpoint_auth_encryption_alg_values_supported', $this->getJWTLoader()->getSupportedKeyEncryptionAlgorithms());
            $this->metadata->set('token_endpoint_auth_encryption_enc_values_supported', $this->getJWTLoader()->getSupportedContentEncryptionAlgorithms());
            $this->metadata->set('display_values_supported', ['page']);
            $this->metadata->set('claim_types_supported', false);
            $this->metadata->set('claims_supported', false);
            $this->metadata->set('service_documentation', 'https://my.server.com/documentation');
            $this->metadata->set('claims_locales_supported', []);
            $this->metadata->set('ui_locales_supported', ['en_US', 'fr_FR']);
            $this->metadata->set('claims_parameter_supported', false);
            $this->metadata->set('request_parameter_supported', $this->getAuthorizationRequestLoader()->isRequestObjectSupportEnabled());
            $this->metadata->set('request_uri_parameter_supported', $this->getAuthorizationRequestLoader()->isRequestObjectReferenceSupportEnabled());
            $this->metadata->set('require_request_uri_registration', true);
            $this->metadata->set('op_policy_uri', 'https://my.server.com/policy.html');
            $this->metadata->set('op_tos_uri', 'https://my.server.com/tos.html');
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
     * @var null|\OAuth2\Endpoint\TokenType\RefreshToken
     */
    private $refresh_token_type = null;

    /**
     * @return \OAuth2\Endpoint\TokenType\RefreshToken
     */
    protected function getRefreshTokenType()
    {
        if (null === $this->refresh_token_type) {
            $this->refresh_token_type = new RefreshToken($this->getRefreshTokenManager());
        }

        return $this->refresh_token_type;
    }

    /**
     * @var null|\OAuth2\Endpoint\TokenType\AuthCode
     */
    private $auth_code_type = null;

    /**
     * @return \OAuth2\Endpoint\TokenType\AuthCode
     */
    protected function getAuthCodeType()
    {
        if (null === $this->auth_code_type) {
            $this->auth_code_type = new AuthCode($this->getAuthCodeManager());
        }

        return $this->auth_code_type;
    }

    /**
     * @var null|\Jose\Object\JWKSetInterface
     */
    private $signature_key_set = null;

    /**
     * @return \Jose\Object\JWKSetInterface
     */
    protected function getSignatureKeySet()
    {
        if (null === $this->signature_key_set) {
            $this->signature_key_set = new JWKSet(['keys' => [
                [
                    'kid' => 'JWK2',
                    'use' => 'sig',
                    'kty' => 'oct',
                    'k'   => 'AyM1SysPpbyDfgZld3umj1qzKObwVMkoqQ-EstJQLr_T-1qS0gZH75aKtMN3Yj0iPS4hcgUuTwjAzZr1Z9CAow',
                ],
            ]]);
        }

        return $this->signature_key_set;
    }

    /**
     * @var null|\Jose\Object\JWKSetInterface
     */
    private $encryption_key_set = null;

    /**
     * @return \Jose\Object\JWKSetInterface
     */
    protected function getEncryptionKeySet()
    {
        if (null === $this->encryption_key_set) {
            $this->encryption_key_set = new JWKSet(['keys' => [
                [
                    'kid' => 'JWK1',
                    'use' => 'enc',
                    'kty' => 'oct',
                    'k'   => 'ABEiM0RVZneImaq7zN3u_wABAgMEBQYHCAkKCwwNDg8',
                ],
            ]]);
        }

        return $this->encryption_key_set;
    }
}
