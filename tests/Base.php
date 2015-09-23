<?php

namespace OAuth2\Test;

use OAuth2\Client\ClientManagerSupervisor;
use OAuth2\Configuration\Configuration;
use OAuth2\Endpoint\AuthorizationEndpoint;
use OAuth2\Endpoint\RevocationEndpoint;
use OAuth2\Endpoint\TokenEndpoint;
use OAuth2\Grant\AuthorizationCodeGrantType;
use OAuth2\Grant\ClientCredentialsGrantType;
use OAuth2\Grant\ImplicitGrantType;
use OAuth2\Grant\JWTBearerGrantType;
use OAuth2\Grant\RefreshTokenGrantType;
use OAuth2\Grant\ResourceOwnerPasswordCredentialsGrantType;
use OAuth2\Test\Stub\AuthCodeManager;
use OAuth2\Test\Stub\EndUserManager;
use OAuth2\Test\Stub\ExceptionManager;
use OAuth2\Test\Stub\JWTAccessTokenManager;
use OAuth2\Test\Stub\JWTClientManager;
use OAuth2\Test\Stub\PasswordClientManager;
use OAuth2\Test\Stub\PublicClientManager;
use OAuth2\Test\Stub\RefreshTokenManager;
use OAuth2\Test\Stub\ScopeManager;
use OAuth2\Test\Stub\SimpleStringAccessTokenManager;
use OAuth2\Test\Stub\UnregisteredClientManager;
use OAuth2\Token\AccessTokenTypeManager;
use OAuth2\Token\BearerAccessToken;
use SpomkyLabs\Service\Jose;
use Symfony\Bridge\PsrHttpMessage\Factory\DiactorosFactory;
use Symfony\Component\HttpFoundation\Request;

class Base extends \PHPUnit_Framework_TestCase
{
    protected function setUp()
    {
        //To fix HHVM tests on Travis-CI
        date_default_timezone_set('UTC');

        // We set the configuration of the Jose Service
        $jose = Jose::getInstance();
        $jose->getConfiguration()->set('algorithms', ['HS512', 'A256KW', 'A256CBC-HS512']);
        $jose->getConfiguration()->set('audience', 'My Authorization Server');

        // We add our shared keys
        $jose->getKeysetManager()->loadKeyFromValues('JWK1', [
            'kid' => 'JWK1',
            'use' => 'enc',
            'kty' => 'oct',
            'k'   => 'ABEiM0RVZneImaq7zN3u_wABAgMEBQYHCAkKCwwNDg8',
        ]);
        $jose->getKeysetManager()->loadKeyFromValues('JWK2', [
            'kid' => 'JWK2',
            'use' => 'sig',
            'kty' => 'oct',
            'k'   => 'AyM1SysPpbyDfgZld3umj1qzKObwVMkoqQ-EstJQLr_T-1qS0gZH75aKtMN3Yj0iPS4hcgUuTwjAzZr1Z9CAow',
        ]);
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
            $this->revocation_endpoint->setAccessTokenManager($this->getSimplestringAccessTokenManager());
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
            $this->token_endpoint->setAccessTokenTypeManager($this->getAccessTokenTypeManager());
            $this->token_endpoint->setAccessTokenManager($this->getSimplestringAccessTokenManager());
            $this->token_endpoint->setEndUserManager($this->getEndUserManager());
            $this->token_endpoint->setClientManagerSupervisor($this->getClientManagerSupervisor());
            $this->token_endpoint->setRefreshTokenManager($this->getRefreshTokenManager());

            $this->token_endpoint->addGrantType($this->getAuthorizationCodeGrantType());
            $this->token_endpoint->addGrantType($this->getClientCredentialsGrantType());
            $this->token_endpoint->addGrantType($this->getRefreshTokenGrantType());
            $this->token_endpoint->addGrantType($this->getResourceOwnerPasswordCredentialsGrantType());
            $this->token_endpoint->addGrantType($this->getJWTBearerGrantType());
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
     * @var null|\OAuth2\Configuration\Configuration
     */
    private $configuration = null;

    /**
     * @return \OAuth2\Configuration\Configuration
     */
    protected function getConfiguration()
    {
        if (is_null($this->configuration)) {
            $this->configuration = new Configuration();
            $this->configuration->set('realm', 'testrealm@host.com');
            $this->configuration->set('digest_authentication_key', 'This is my secret key');
            $this->configuration->set('digest_authentication_scheme_algorithm', 'MD5-sess');
            $this->configuration->set('digest_authentication_nonce_lifetime', 300);
            $this->configuration->set('jwt_access_token_audience', 'My Authorization Server');
            $this->configuration->set('jwt_access_token_issuer', 'My Authorization Server');
            $this->configuration->set('jwt_access_token_signature_algorithm', 'HS512');
            $this->configuration->set('jwt_access_token_encrypted', true);
            $this->configuration->set('jwt_access_token_key_encryption_algorithm', 'A256KW');
            $this->configuration->set('jwt_access_token_content_encryption_algorithm', 'A256CBC-HS512');
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
            $this->client_manager_supervisor->setConfiguration($this->getConfiguration());

            $this->client_manager_supervisor->addClientManager($this->getUnregisteredClientManager());
            $this->client_manager_supervisor->addClientManager($this->getPasswordClientManager());
            $this->client_manager_supervisor->addClientManager($this->getPublicClientManager());
            $this->client_manager_supervisor->addClientManager($this->getJWTClientManager());
        }

        return $this->client_manager_supervisor;
    }

    /**
     * @var null|\OAuth2\Test\Stub\UnregisteredClientManager
     */
    private $unregistered_client_manager = null;

    /**
     * @return \OAuth2\Test\Stub\UnregisteredClientManager
     */
    protected function getUnregisteredClientManager()
    {
        if (is_null($this->unregistered_client_manager)) {
            $this->unregistered_client_manager = new UnregisteredClientManager();
            $this->unregistered_client_manager->setExceptionManager($this->getExceptionManager());
        }

        return $this->unregistered_client_manager;
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
            $this->password_client_manager->createClients();
        }

        return $this->password_client_manager;
    }

    /**
     * @var null|\OAuth2\Test\Stub\JWTClientManager
     */
    private $jwt_client_manager = null;

    /**
     * @return \OAuth2\Test\Stub\JWTClientManager
     */
    protected function getJWTClientManager()
    {
        if (is_null($this->jwt_client_manager)) {
            $jose = Jose::getInstance();

            $this->jwt_client_manager = new JWTClientManager();
            $this->jwt_client_manager->setExceptionManager($this->getExceptionManager());
            $this->jwt_client_manager->setConfiguration($this->getConfiguration());
            $this->jwt_client_manager->setJWTLoader($jose->getLoader());
            $this->jwt_client_manager->setKeySetManager($jose->getKeysetManager());
            $this->jwt_client_manager->setAllowedEncryptionAlgorithms(['A256KW', 'A256CBC-HS512']);
            $this->jwt_client_manager->setPrivateKeySet(
                ['keys' => [
                        'kid' => 'JWK1',
                        'use' => 'enc',
                        'kty' => 'oct',
                        'k'   => 'ABEiM0RVZneImaq7zN3u_wABAgMEBQYHCAkKCwwNDg8',
                    ],
                    [
                        'kid' => 'JWK2',
                        'use' => 'sig',
                        'kty' => 'oct',
                        'k'   => 'AyM1SysPpbyDfgZld3umj1qzKObwVMkoqQ-EstJQLr_T-1qS0gZH75aKtMN3Yj0iPS4hcgUuTwjAzZr1Z9CAow',
                    ],
                ]
            );
        }

        return $this->jwt_client_manager;
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
     * @var null|\OAuth2\Grant\JWTBearerGrantType
     */
    private $jwt_bearer_grant_type = null;

    /**
     * @return \OAuth2\Grant\JWTBearerGrantType
     */
    protected function getJWTBearerGrantType()
    {
        if (is_null($this->jwt_bearer_grant_type)) {
            $jose = Jose::getInstance();
            $this->jwt_bearer_grant_type = new JWTBearerGrantType();
            $this->jwt_bearer_grant_type->setExceptionManager($this->getExceptionManager());
            $this->jwt_bearer_grant_type->setConfiguration($this->getConfiguration());
            $this->jwt_bearer_grant_type->setJWTLoader($jose->getLoader());
            $this->jwt_bearer_grant_type->setKeySetManager($jose->getKeysetManager());
            $this->jwt_bearer_grant_type->setAllowedEncryptionAlgorithms(['A256KW', 'A256CBC-HS512']);
            $this->jwt_bearer_grant_type->setPrivateKeySet(
                ['keys' => [
                        'kid' => 'JWK1',
                        'use' => 'enc',
                        'kty' => 'oct',
                        'k'   => 'ABEiM0RVZneImaq7zN3u_wABAgMEBQYHCAkKCwwNDg8',
                    ],
                    [
                        'kid' => 'JWK2',
                        'use' => 'sig',
                        'kty' => 'oct',
                        'k'   => 'AyM1SysPpbyDfgZld3umj1qzKObwVMkoqQ-EstJQLr_T-1qS0gZH75aKtMN3Yj0iPS4hcgUuTwjAzZr1Z9CAow',
                    ],
                ]
            );
        }

        return $this->jwt_bearer_grant_type;
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
            $this->implicit_grant_type->setAccessTokenManager($this->getSimplestringAccessTokenManager());
            $this->implicit_grant_type->setAccessTokenTypeManager($this->getAccessTokenTypeManager());
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
    private $simple_string_access_token_manager = null;

    /**
     * @return \OAuth2\Test\Stub\SimpleStringAccessTokenManager
     */
    protected function getSimpleStringAccessTokenManager()
    {
        if (is_null($this->simple_string_access_token_manager)) {
            $this->simple_string_access_token_manager = new SimpleStringAccessTokenManager();
            $this->simple_string_access_token_manager->setConfiguration($this->getConfiguration());
            $this->simple_string_access_token_manager->setExceptionManager($this->getExceptionManager());
        }

        return $this->simple_string_access_token_manager;
    }

    /**
     * @return null|\OAuth2\Test\Stub\JWTAccessTokenManager
     */
    private $jwt_access_token_manager = null;

    /**
     * @return \OAuth2\Test\Stub\JWTAccessTokenManager
     */
    protected function getJWTAccessTokenManager()
    {
        if (is_null($this->jwt_access_token_manager)) {
            $this->jwt_access_token_manager = new JWTAccessTokenManager();
            $this->jwt_access_token_manager->setConfiguration($this->getConfiguration());
            $this->jwt_access_token_manager->setExceptionManager($this->getExceptionManager());
        }

        return $this->jwt_access_token_manager;
    }

    /**
     * @return null|\OAuth2\Token\BearerAccessToken
     */
    private $bearer_access_token_type = null;

    /**
     * @return \OAuth2\Token\BearerAccessToken
     */
    protected function getBearerAccessTokenType()
    {
        if (is_null($this->bearer_access_token_type)) {
            $this->bearer_access_token_type = new BearerAccessToken();
            $this->bearer_access_token_type->setExceptionManager($this->getExceptionManager());
        }

        return $this->bearer_access_token_type;
    }

    /**
     * @return null|\OAuth2\Token\AccessTokenTypeManagerInterface
     */
    private $access_token_type_manager = null;

    /**
     * @return \OAuth2\Token\AccessTokenTypeManagerInterface
     */
    protected function getAccessTokenTypeManager()
    {
        if (is_null($this->access_token_type_manager)) {
            $this->access_token_type_manager = new AccessTokenTypeManager();
            $this->access_token_type_manager->setExceptionManager($this->getExceptionManager());
            $this->access_token_type_manager->addAccessTokenType($this->getBearerAccessTokenType());
        }

        return $this->access_token_type_manager;
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

    protected function createValidDigest($method, $uri, $client_id, $client_secret, $qop = 'auth', $content = null)
    {
        $expiryTime = microtime(true) + $this->getConfiguration()->get('digest_authentication_nonce_lifetime', 300) * 1000;
        $signatureValue = md5($expiryTime.':'.$this->getConfiguration()->get('digest_authentication_key'));
        $nonceValue = $expiryTime.':'.$signatureValue;
        $nonceValueBase64 = base64_encode($nonceValue);

        $cnonce = uniqid();

        $ha1 = hash('md5', sprintf('%s:%s:%s', $client_id, $this->getConfiguration()->get('realm', 'Service'), $client_secret));
        if ('MD5-sess' === $this->getConfiguration()->get('digest_authentication_scheme_algorithm', null)) {
            $ha1 = hash('md5', sprintf('%s:%s:%s', $ha1, $nonceValueBase64, $cnonce));
        }

        $a2 = sprintf('%s:%s', $method, $uri);
        if ('auth-int' === $qop) {
            $a2 .= ':'.hash('md5', $content);
        }
        $ha2 = hash('md5', $a2);
        $response = hash('md5', sprintf(
            '%s:%s:%s:%s:%s:%s',
            $ha1,
            $nonceValueBase64,
            '00000001',
            $cnonce,
            $qop,
            $ha2
        ));

        return sprintf(
            'username="%s",realm="%s",nonce="%s",uri="%s",qop=%s,nc=00000001,cnonce="%s",response="%s",opaque="%s"',
            $client_id,
            $this->getConfiguration()->get('realm', 'Service'),
            $nonceValueBase64,
            $uri,
            $qop,
            $cnonce,
            $response,
            hash('md5', $this->getConfiguration()->get('realm', 'Service'))
        );
    }
}
