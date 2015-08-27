<?php

namespace OAuth2\Test;

use OAuth2\Client\ClientManagerSupervisor;
use OAuth2\Endpoint\AuthorizationEndpoint;
use OAuth2\Endpoint\RevocationEndpoint;
use OAuth2\Endpoint\TokenEndpoint;
use OAuth2\Grant\AuthorizationCodeGrantType;
use OAuth2\Grant\ClientCredentialsGrantType;
use OAuth2\Grant\ImplicitGrantType;
use OAuth2\Grant\RefreshTokenGrantType;
use OAuth2\Grant\ResourceOwnerPasswordCredentialsGrantType;
use OAuth2\Test\Stub\AuthCodeManager;
use OAuth2\Test\Stub\Configuration;
use OAuth2\Test\Stub\EndUserManager;
use OAuth2\Test\Stub\ExceptionManager;
use OAuth2\Test\Stub\PasswordClientManager;
use OAuth2\Test\Stub\PublicClientManager;
use OAuth2\Test\Stub\RefreshTokenManager;
use OAuth2\Test\Stub\ScopeManager;
use OAuth2\Test\Stub\SimpleStringAccessTokenManager;
use OAuth2\Token\BearerAccessToken;
use Symfony\Component\HttpFoundation\Request;

class Base extends \PHPUnit_Framework_TestCase
{
    protected function setUp()
    {
        //To fix HHVM tests on Travis-CI
        date_default_timezone_set('UTC');
    }

    /**
     * @param string      $uri
     * @param string      $method
     * @param array       $parameters
     * @param array       $server
     * @param array       $headers
     * @param null|string $content
     *
     * @return \Symfony\Component\HttpFoundation\Request
     */
    protected function createRequest($uri = '/', $method = 'GET', array $parameters = [], array $server = [], array $headers = [], $content = null)
    {
        $request = Request::create($uri, $method, $parameters, [], [], $server, $content);
        foreach ($headers as $key => $value) {
            $request->headers->set($key, $value);
        }

        return $request;
    }
    /**
     * @var null|\OAuth2\Endpoint\RevocationEndpoint
     */
    private $revocation_endpoint = null;

    /**
     * @return \OAuth2\Endpoint\RevocationEndpoint
     */
    protected function getRevocationTokenEndpoint()
    {
        if (is_null($this->revocation_endpoint)) {
            $this->revocation_endpoint = new RevocationEndpoint();
            $this->revocation_endpoint->setAccessTokenManager($this->getAccessTokenManager());
            $this->revocation_endpoint->setConfiguration($this->getConfiguration());
            $this->revocation_endpoint->setExceptionManager($this->getExceptionManager());
            $this->revocation_endpoint->setClientManagerSupervisor($this->getClientManagerSupervisor());
            $this->revocation_endpoint->setRefreshTokenManager($this->getRefreshTokenManager());
        }

        return $this->revocation_endpoint;
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
        if (is_null($this->token_endpoint)) {
            $this->token_endpoint = new TokenEndpoint();
            $this->token_endpoint->setExceptionManager($this->getExceptionManager());
            $this->token_endpoint->setScopeManager($this->getScopeManager());
            $this->token_endpoint->setAccessTokenType($this->getAccessTokenType());
            $this->token_endpoint->setAccessTokenManager($this->getAccessTokenManager());
            $this->token_endpoint->setEndUserManager($this->getEndUserManager());
            $this->token_endpoint->setClientManagerSupervisor($this->getClientManagerSupervisor());
            $this->token_endpoint->setRefreshTokenManager($this->getRefreshTokenManager());

            $this->token_endpoint->addGrantType($this->getAuthorizationCodeGrantType());
            $this->token_endpoint->addGrantType($this->getClientCredentialsGrantType());
            $this->token_endpoint->addGrantType($this->getRefreshTokenGrantType());
            $this->token_endpoint->addGrantType($this->getResourceOwnerPasswordCredentialsGrantType());
        }

        return $this->token_endpoint;
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
        if (is_null($this->authorization_endpoint)) {
            $this->authorization_endpoint = new AuthorizationEndpoint();
            $this->authorization_endpoint->setConfiguration($this->getConfiguration());
            $this->authorization_endpoint->setExceptionManager($this->getExceptionManager());
            $this->authorization_endpoint->setScopeManager($this->getScopeManager());

            $this->authorization_endpoint->addResponseType($this->getAuthorizationCodeGrantType());
            $this->authorization_endpoint->addResponseType($this->getImplicitGrantType());
        }

        return $this->authorization_endpoint;
    }

    /**
     * @var null|\OAuth2\Test\Stub\Configuration
     */
    private $configuration = null;

    /**
     * @return \OAuth2\Test\Stub\Configuration
     */
    protected function getConfiguration()
    {
        if (is_null($this->configuration)) {
            $this->configuration = new Configuration();
        }

        return $this->configuration;
    }

    /**
     * @var null|\OAuth2\Test\Stub\ExceptionManager
     */
    private $exception_manager = null;

    /**
     * @return \OAuth2\Test\Stub\ExceptionManager
     */
    protected function getExceptionManager()
    {
        if (is_null($this->exception_manager)) {
            $this->exception_manager = new ExceptionManager();
            $this->exception_manager->setConfiguration($this->getConfiguration());
        }

        return $this->exception_manager;
    }

    /**
     * @var null|\OAuth2\Test\Stub\EndUserManager
     */
    private $end_user_manager = null;

    /**
     * @return \OAuth2\Test\Stub\EndUserManager
     */
    protected function getEndUserManager()
    {
        if (is_null($this->end_user_manager)) {
            $this->end_user_manager = new EndUserManager();
        }

        return $this->end_user_manager;
    }

    /**
     * @var null|\OAuth2\Client\ClientManagerSupervisor
     */
    private $client_manager_supervisor = null;

    /**
     * @return \OAuth2\Client\ClientManagerSupervisor
     */
    protected function getClientManagerSupervisor()
    {
        if (is_null($this->client_manager_supervisor)) {
            $this->client_manager_supervisor = new ClientManagerSupervisor();
            $this->client_manager_supervisor->setExceptionManager($this->getExceptionManager());

            $this->client_manager_supervisor->addClientManager($this->getPasswordClientManager());
            $this->client_manager_supervisor->addClientManager($this->getPublicClientManager());
        }

        return $this->client_manager_supervisor;
    }

    /**
     * @var null|\OAuth2\Test\Stub\PublicClientManager
     */
    private $public_client_manager = null;

    /**
     * @return \OAuth2\Test\Stub\PublicClientManager
     */
    protected function getPublicClientManager()
    {
        if (is_null($this->public_client_manager)) {
            $this->public_client_manager = new PublicClientManager();
            $this->public_client_manager->setExceptionManager($this->getExceptionManager());
        }

        return $this->public_client_manager;
    }

    /**
     * @var null|\OAuth2\Test\Stub\PasswordClientManager
     */
    private $password_client_manager = null;

    /**
     * @return \OAuth2\Test\Stub\PasswordClientManager
     */
    protected function getPasswordClientManager()
    {
        if (is_null($this->password_client_manager)) {
            $this->password_client_manager = new PasswordClientManager();
            $this->password_client_manager->setExceptionManager($this->getExceptionManager());
            $this->password_client_manager->setConfiguration($this->getConfiguration());
        }

        return $this->password_client_manager;
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
        if (is_null($this->authorization_code_grant_type)) {
            $this->authorization_code_grant_type = new AuthorizationCodeGrantType();
            $this->authorization_code_grant_type->setExceptionManager($this->getExceptionManager());
            $this->authorization_code_grant_type->setAuthCodeManager($this->getAuthCodeManager());
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
        if (is_null($this->client_credentials_grant_type)) {
            $this->client_credentials_grant_type = new ClientCredentialsGrantType();
            $this->client_credentials_grant_type->setExceptionManager($this->getExceptionManager());
            $this->client_credentials_grant_type->setConfiguration($this->getConfiguration());
        }

        return $this->client_credentials_grant_type;
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
        if (is_null($this->implicit_grant_type)) {
            $this->implicit_grant_type = new ImplicitGrantType();
            $this->implicit_grant_type->setAccessTokenManager($this->getAccessTokenManager());
            $this->implicit_grant_type->setAccessTokenType($this->getAccessTokenType());
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
        if (is_null($this->refresh_token_grant_type)) {
            $this->refresh_token_grant_type = new RefreshTokenGrantType();
            $this->refresh_token_grant_type->setRefreshTokenManager($this->getRefreshTokenManager());
            $this->refresh_token_grant_type->setExceptionManager($this->getExceptionManager());
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
        if (is_null($this->resource_owner_password_credentials_grant_type)) {
            $this->resource_owner_password_credentials_grant_type = new ResourceOwnerPasswordCredentialsGrantType();
            $this->resource_owner_password_credentials_grant_type->setConfiguration($this->getConfiguration());
            $this->resource_owner_password_credentials_grant_type->setExceptionManager($this->getExceptionManager());
            $this->resource_owner_password_credentials_grant_type->setEndUserManager($this->getEndUserManager());
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
        if (is_null($this->scope_manager)) {
            $this->scope_manager = new ScopeManager();
            $this->scope_manager->setExceptionManager($this->getExceptionManager());
        }

        return $this->scope_manager;
    }

    /**
     * @return null|\OAuth2\Test\Stub\SimpleStringAccessTokenManager
     */
    private $access_token_manager = null;

    /**
     * @return \OAuth2\Test\Stub\SimpleStringAccessTokenManager
     */
    protected function getAccessTokenManager()
    {
        if (is_null($this->access_token_manager)) {
            $this->access_token_manager = new SimpleStringAccessTokenManager();
            $this->access_token_manager->setConfiguration($this->getConfiguration());
            $this->access_token_manager->setExceptionManager($this->getExceptionManager());
        }

        return $this->access_token_manager;
    }

    /**
     * @return null|\OAuth2\Token\BearerAccessToken
     */
    private $access_token_type = null;

    /**
     * @return \OAuth2\Token\BearerAccessToken
     */
    protected function getAccessTokenType()
    {
        if (is_null($this->access_token_type)) {
            $this->access_token_type = new BearerAccessToken();
            $this->access_token_type->setExceptionManager($this->getExceptionManager());
        }

        return $this->access_token_type;
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
        if (is_null($this->refresh_token_manager)) {
            $this->refresh_token_manager = new RefreshTokenManager();
            $this->refresh_token_manager->setConfiguration($this->getConfiguration());
            $this->refresh_token_manager->setExceptionManager($this->getExceptionManager());
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
        if (is_null($this->auth_code_manager)) {
            $this->auth_code_manager = new AuthCodeManager();
            $this->auth_code_manager->setConfiguration($this->getConfiguration());
            $this->auth_code_manager->setExceptionManager($this->getExceptionManager());
        }

        return $this->auth_code_manager;
    }
}
