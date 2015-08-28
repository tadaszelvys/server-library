<?php

namespace OAuth2\Token;

use OAuth2\Behaviour\HasConfiguration;
use OAuth2\Behaviour\HasExceptionManager;
use OAuth2\Client\ClientInterface;
use OAuth2\Client\TokenLifetimeExtensionInterface;
use OAuth2\Exception\ExceptionManagerInterface;
use OAuth2\ResourceOwner\ResourceOwnerInterface;
use Security\DefuseGenerator;

abstract class AuthCodeManager implements AuthCodeManagerInterface
{
    use HasExceptionManager;
    use HasConfiguration;

    /**
     * Generate and add an Authorization Code using the parameters.
     *
     * @param string                                       $code              Code
     * @param int                                          $expiresAt         Time until the code is valid
     * @param ClientInterface                              $client            Client
     * @param string                                       $redirectUri       Redirect URI
     * @param string[ ]              $scope             Scope
     * @param \OAuth2\ResourceOwner\ResourceOwnerInterface $resourceOwner     Resource owner
     * @param bool                                         $issueRefreshToken Issue a refresh token with the access token
     *
     * @return \OAuth2\Token\AuthCodeInterface
     */
    abstract protected function addAuthCode($code, $expiresAt, ClientInterface $client, $redirectUri, array $scope = [], ResourceOwnerInterface $resourceOwner = null, $issueRefreshToken = false);

    /**
     * {@inheritdoc}
     */
    public function createAuthCode(ClientInterface $client, $redirectUri, array $scope = [], ResourceOwnerInterface $resourceOwner = null, $issueRefreshToken = false)
    {
        $length = $this->getConfiguration()->get('auth_code_length', 20);
        $charset = $this->getConfiguration()->get('auth_code_charset', 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._~+/');
        try {
            $code = DefuseGenerator::getRandomString($length, $charset);
        } catch (\Exception $e) {
            throw $this->createException($e->getMessage());
        }
        if (!is_string($code) || strlen($code) !== $length) {
            throw $this->createException('An error has occurred during the creation of the authorization code.');
        }

        $authcode = $this->addAuthCode($code, time() + $this->getLifetime($client), $client, $redirectUri, $scope, $resourceOwner, $issueRefreshToken);

        return $authcode;
    }

    /**
     * {@inheritdoc}
     */
    protected function getLifetime(ClientInterface $client)
    {
        $lifetime = $this->getConfiguration()->get('auth_code_lifetime', 30);
        if ($client instanceof TokenLifetimeExtensionInterface && ($_lifetime = $client->getTokenLifetime('authcode')) !== null) {
            return $_lifetime;
        }

        return $lifetime;
    }

    private function createException($message)
    {
        return $this->getExceptionManager()->getException(ExceptionManagerInterface::INTERNAL_SERVER_ERROR, 'authcode_creation_error', $message);
    }
}
