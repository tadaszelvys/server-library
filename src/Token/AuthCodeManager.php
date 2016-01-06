<?php

/*
 * The MIT License (MIT)
 *
 * Copyright (c) 2014-2016 Spomky-Labs
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file for details.
 */

namespace OAuth2\Token;

use OAuth2\Behaviour\HasConfiguration;
use OAuth2\Behaviour\HasExceptionManager;
use OAuth2\Client\ClientInterface;
use OAuth2\Client\TokenLifetimeExtensionInterface;
use OAuth2\Configuration\ConfigurationInterface;
use OAuth2\EndUser\EndUserInterface;
use OAuth2\Exception\ExceptionManagerInterface;
use Security\DefuseGenerator;

abstract class AuthCodeManager implements AuthCodeManagerInterface
{
    use HasExceptionManager;
    use HasConfiguration;

    /**
     * AuthCodeManager constructor.
     *
     * @param \OAuth2\Exception\ExceptionManagerInterface  $exception_manager
     * @param \OAuth2\Configuration\ConfigurationInterface $configuration
     */
    public function __construct(ExceptionManagerInterface $exception_manager, ConfigurationInterface $configuration)
    {
        $this->setExceptionManager($exception_manager);
        $this->setConfiguration($configuration);
    }

    /**
     * Generate and add an Authorization Code using the parameters.
     *
     * @param string                           $code              Code
     * @param int                              $expiresAt         Time until the code is valid
     * @param \OAuth2\Client\ClientInterface   $client            Client
     * @param \OAuth2\EndUser\EndUserInterface $end_user          Resource owner
     * @param array                            $query_params      The authorization request query parameters.
     * @param string                           $redirectUri       Redirect URI
     * @param string[ ]                        $scope             Scope
     * @param bool                             $issueRefreshToken Issue a refresh token with the access token
     *
     * @return \OAuth2\Token\AuthCodeInterface
     */
    abstract protected function addAuthCode($code, $expiresAt, ClientInterface $client, EndUserInterface $end_user, array $query_params, $redirectUri, array $scope = [], $issueRefreshToken = false);

    /**
     * {@inheritdoc}
     */
    public function createAuthCode(ClientInterface $client, EndUserInterface $end_user, array $query_params, $redirectUri, array $scope = [], $issueRefreshToken = false)
    {
        $length = $this->getAuthCodeLength();
        $charset = $this->getConfiguration()->get('auth_code_charset', 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._~+/');
        try {
            $code = DefuseGenerator::getRandomString($length, $charset);
        } catch (\Exception $e) {
            throw $this->createException($e->getMessage());
        }
        if (!is_string($code) || strlen($code) !== $length) {
            throw $this->createException('An error has occurred during the creation of the authorization code.');
        }

        $authcode = $this->addAuthCode($code, time() + $this->getLifetime($client), $client, $end_user, $query_params, $redirectUri, $scope, $issueRefreshToken);

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

    /**
     * @throws \OAuth2\Exception\BaseExceptionInterface
     *
     * @return int
     */
    private function getAuthCodeLength()
    {
        $min_length = $this->getConfiguration()->get('auth_code_min_length', 20);
        $max_length = $this->getConfiguration()->get('auth_code_max_length', 30);
        srand();

        return rand(min($min_length, $max_length), max($min_length, $max_length));
    }

    /**
     * @param string $message
     *
     * @return \OAuth2\Exception\BaseExceptionInterface
     */
    private function createException($message)
    {
        return $this->getExceptionManager()->getException(ExceptionManagerInterface::INTERNAL_SERVER_ERROR, ExceptionManagerInterface::SERVER_ERROR, $message);
    }
}
