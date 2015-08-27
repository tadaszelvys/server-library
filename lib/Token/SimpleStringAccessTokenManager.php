<?php

namespace OAuth2\Token;

use OAuth2\Behaviour\HasExceptionManager;
use OAuth2\Client\ClientInterface;
use OAuth2\Exception\ExceptionManagerInterface;
use OAuth2\ResourceOwner\ResourceOwnerInterface;
use Security\DefuseGenerator;

abstract class SimpleStringAccessTokenManager extends AccessTokenManager
{
    use HasExceptionManager;

    /**
     * Generate and add an Authorization Code using the parameters.
     *
     * @param string                                       $token         Code
     * @param int                                          $expiresAt     Time until the code is valid
     * @param \OAuth2\Client\ClientInterface               $client        Client
     * @param \OAuth2\Scope\ScopeInterface[]               $scope         Scope
     * @param \OAuth2\ResourceOwner\ResourceOwnerInterface $resourceOwner Resource owner
     * @param \OAuth2\Token\RefreshTokenInterface          $refresh_token Refresh token
     *
     * @return \OAuth2\Token\AccessTokenInterface
     */
    abstract protected function addAccessToken($token, $expiresAt, ClientInterface $client, array $scope = array(), ResourceOwnerInterface $resourceOwner = null, RefreshTokenInterface $refresh_token = null);

    /**
     * {@inheritdoc}
     *
     * @throws \OAuth2\Exception\BaseExceptionInterface
     */
    public function createAccessToken(ClientInterface $client, array $scope = array(), ResourceOwnerInterface $resourceOwner = null, RefreshTokenInterface $refresh_token = null)
    {
        $length = $this->getConfiguration()->get('simple_string_access_token_length', 20);
        $charset = $this->getConfiguration()->get('simple_string_access_token_charset', 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._~+/');
        try {
            $token = DefuseGenerator::getRandomString($length, $charset);
        } catch (\Exception $e) {
            throw $this->createException($e->getMessage());
        }
        if (!is_string($token) || strlen($token) !== $length) {
            throw $this->createException('An error has occurred during the creation of the token.');
        }

        $access_token = $this->addAccessToken($token, time() + $this->getLifetime($client), $client, $scope, $resourceOwner, $refresh_token);

        return $access_token;
    }

    private function createException($message)
    {
        return $this->getExceptionManager()->getException(ExceptionManagerInterface::INTERNAL_SERVER_ERROR, 'token_creation_error', $message);
    }
}
