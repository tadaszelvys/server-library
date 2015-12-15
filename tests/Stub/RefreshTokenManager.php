<?php

namespace OAuth2\Test\Stub;

use OAuth2\Client\ClientInterface;
use OAuth2\Configuration\ConfigurationInterface;
use OAuth2\Exception\ExceptionManagerInterface;
use OAuth2\ResourceOwner\ResourceOwnerInterface;
use OAuth2\Token\RefreshToken;
use OAuth2\Token\RefreshTokenInterface;
use OAuth2\Token\RefreshTokenManager as Base;
use OAuth2\Token\RefreshTokenManagerInterface;

class RefreshTokenManager extends Base implements RefreshTokenManagerInterface
{
    /**
     * @var \OAuth2\Token\RefreshToken[]
     */
    private $refresh_tokens = [];

    /**
     * ClientCredentialsGrantType constructor.
     *
     * @param \OAuth2\Exception\ExceptionManagerInterface  $exception_manager
     * @param \OAuth2\Configuration\ConfigurationInterface $configuration
     */
    public function __construct(ExceptionManagerInterface $exception_manager, ConfigurationInterface $configuration)
    {
        parent::__construct($exception_manager, $configuration);

        $bar = new PasswordClient();
        $bar->setSecret('secret');
        $bar->setRedirectUris(['http://example.com/test?good=false']);
        $bar->setAllowedGrantTypes(['client_credentials', 'password', 'token', 'refresh_token', 'code', 'authorization_code']);
        $bar->setPublicId('bar');

        $foo = new PublicClient();
        $foo->setRedirectUris(['http://example.com/test?good=false', 'https://another.uri/callback']);
        $foo->setAllowedGrantTypes(['client_credentials', 'password', 'token', 'refresh_token', 'code', 'authorization_code']);
        $foo->setPublicId('foo');

        $this->addRefreshToken(
            'VALID_REFRESH_TOKEN',
            time() + 10000,
            $bar,
            $bar,
            ['scope1', 'scope2', 'scope3']
        );
        $this->addRefreshToken(
            'EXPIRED_REFRESH_TOKEN',
            time() - 1,
            $foo,
            $foo,
            ['scope1', 'scope2', 'scope3']
        );

        $this->addRefreshToken(
            'REFRESH_EFGH',
            time() + 36000,
            $foo,
            $foo,
            []
        );
    }

    public function getRefreshTokens()
    {
        return array_keys($this->refresh_tokens);
    }

    protected function addRefreshToken($token, $expiresAt, ClientInterface $client, ResourceOwnerInterface $resourceOwner, array $scope = [])
    {
        $refresh_token = new RefreshToken();
        $refresh_token->setUsed(false);
        $refresh_token->setExpiresAt($expiresAt);
        $refresh_token->setToken($token);
        $refresh_token->setClientPublicId($client->getPublicId());
        $refresh_token->setResourceOwnerPublicId(null === $resourceOwner ? null : $resourceOwner->getPublicId());
        $refresh_token->setScope($scope);

        $this->refresh_tokens[$refresh_token->getToken()] = $refresh_token;

        return $refresh_token;
    }

    public function getRefreshToken($token)
    {
        return isset($this->refresh_tokens[$token]) ? $this->refresh_tokens[$token] : null;
    }

    public function markRefreshTokenAsUsed(RefreshTokenInterface $token)
    {
        if (isset($this->refresh_tokens[$token->getToken()])) {
            $token->setUsed(true);
            $this->refresh_tokens[$token->getToken()] = $token;
        }
    }

    public function revokeRefreshToken(RefreshTokenInterface $refresh_token)
    {
        if (isset($this->refresh_tokens[$refresh_token->getToken()])) {
            unset($this->refresh_tokens[$refresh_token->getToken()]);
        }

        return $this;
    }
}
