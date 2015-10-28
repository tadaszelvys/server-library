<?php

namespace OAuth2\Token;

use OAuth2\Behaviour\HasConfiguration;
use OAuth2\Behaviour\HasExceptionManager;
use OAuth2\Client\ClientInterface;
use OAuth2\Client\TokenLifetimeExtensionInterface;
use OAuth2\Exception\ExceptionManagerInterface;
use OAuth2\ResourceOwner\ResourceOwnerInterface;
use Security\DefuseGenerator;

abstract class RefreshTokenManager implements RefreshTokenManagerInterface
{
    use HasExceptionManager;
    use HasConfiguration;

    /**
     * Generate and add a Refresh Token using the parameters.
     *
     * @param string                                       $token         Token
     * @param int                                          $expiresAt     Time until the code is valid
     * @param \OAuth2\Client\ClientInterface               $client        Client
     * @param \OAuth2\ResourceOwner\ResourceOwnerInterface $resourceOwner Resource owner
     * @param string[]                                     $scope         Scope
     *
     * @return \OAuth2\Token\RefreshTokenInterface
     */
    abstract protected function addRefreshToken($token, $expiresAt, ClientInterface $client, ResourceOwnerInterface $resourceOwner, array $scope = []);

    /**
     * {@inheritdoc}
     */
    public function createRefreshToken(ClientInterface $client, ResourceOwnerInterface $resourceOwner, array $scope = [])
    {
        $length = $this->getRefreshTokenLength();
        $charset = $this->getConfiguration()->get('refresh_token_charset', 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._~+/');
        try {
            $token = DefuseGenerator::getRandomString($length, $charset);
        } catch (\Exception $e) {
            throw $this->createException($e->getMessage());
        }
        if (!is_string($token) || strlen($token) !== $length) {
            throw $this->createException('An error has occurred during the creation of the refresh token.');
        }

        $refresh_token = $this->addRefreshToken($token, time() + $this->getLifetime($client), $client, $resourceOwner, $scope);

        return $refresh_token;
    }

    /**
     * @param \OAuth2\Client\ClientInterface $client Client
     *
     * @return int
     */
    protected function getLifetime(ClientInterface $client)
    {
        if ($client instanceof TokenLifetimeExtensionInterface && ($lifetime = $client->getTokenLifetime('refresh_token')) !== null) {
            return $lifetime;
        }

        return  $this->getConfiguration()->get('refresh_token_lifetime', 1209600);
    }

    /**
     * @throws \OAuth2\Exception\BaseExceptionInterface
     *
     * @return int
     */
    private function getRefreshTokenLength()
    {
        $min_length = $this->getConfiguration()->get('refresh_token_min_length', 20);
        $max_length = $this->getConfiguration()->get('refresh_token_max_length', 30);
        if ($min_length > $max_length) {
            throw $this->createException('Invalid configuration: "refresh_token_min_length" value must be lower thant "refresh_token_max_length"');
        }
        srand();

        return rand($min_length, $max_length);
    }

    /**
     * @param $message
     *
     * @return \OAuth2\Exception\BaseExceptionInterface
     */
    private function createException($message)
    {
        return $this->getExceptionManager()->getException(ExceptionManagerInterface::INTERNAL_SERVER_ERROR, ExceptionManagerInterface::SERVER_ERROR, $message);
    }
}
