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
use OAuth2\Behaviour\HasJWTLoader;
use OAuth2\Behaviour\HasJWTSigner;
use OAuth2\Client\ClientInterface;
use OAuth2\Client\TokenLifetimeExtensionInterface;
use OAuth2\Configuration\ConfigurationInterface;
use OAuth2\EndUser\EndUserInterface;
use OAuth2\Exception\ExceptionManagerInterface;
use OAuth2\Util\JWTLoader;
use OAuth2\Util\JWTSigner;

class IdTokenManager implements IdTokenManagerInterface
{
    use HasJWTSigner;
    use HasJWTLoader;
    use HasConfiguration;
    use HasExceptionManager;

    /**
     * IdTokenManager constructor.
     *
     * @param \OAuth2\Util\JWTLoader                       $jwt_loader
     * @param \OAuth2\Util\JWTSigner                       $jwt_signer
     * @param \OAuth2\Exception\ExceptionManagerInterface  $exception_manager
     * @param \OAuth2\Configuration\ConfigurationInterface $configuration
     */
    public function __construct(JWTLoader $jwt_loader, JWTSigner $jwt_signer, ExceptionManagerInterface $exception_manager, ConfigurationInterface $configuration)
    {
        $this->setJWTLoader($jwt_loader);
        $this->setJWTSigner($jwt_signer);
        $this->setExceptionManager($exception_manager);
        $this->setConfiguration($configuration);
    }

    /**
     * @param \OAuth2\Token\IdTokenInterface $is_token
     */
    protected function saveIdToken(IdTokenInterface $is_token)
    {
        //Nothing to do
    }

    /**
     * {@inheritdoc}
     */
    public function createIdToken(ClientInterface $client, EndUserInterface $end_user, $at_hash = null, $c_hash = null)
    {
        $id_token = $this->createEmptyIdToken();

        $exp = time() + $this->getLifetime($client);

        $headers = [
            'typ'       => 'JWT',
            'iat'       => time(),
            'nbf'       => time(),
            'exp'       => $exp,
            'alg'       => $this->getSignatureAlgorithm(),
            'auth_time' => $end_user->getLastLoginAt(),
        ];

        $payload = [
            'iss' => 'My server',
            'sub' => $end_user->getPublicId(),
            'aud' => $client->getPublicId(),
        ];
        if (null !== $at_hash) {
            //$payload['at_hash'] = $this->
        }
        $jws = $this->getJWTSigner()->sign($payload, $headers);

        $id_token->setExpiresAt($exp);
        $id_token->setClientPublicId($client->getPublicId());
        $id_token->setResourceOwnerPublicId($end_user->getPublicId());
        $id_token->setToken($jws);

        $this->saveIdToken($id_token);

        return $id_token;
    }

    /**
     * {@inheritdoc}
     */
    public function revokeIdToken(IdTokenInterface $token)
    {
        //Not supported
    }

    /**
     * {@inheritdoc}
     */
    public function getIdToken($data)
    {
        $jws = $this->getJWTLoader()->load($data);
        // TODO: Verify signature here

        $id_token = $this->createEmptyIdToken();
        $id_token->setToken($data);
        $id_token->setExpiresAt($jws->getHeader('exp'));
        $id_token->setClientPublicId($jws->getClaim('aud'));
        $id_token->setResourceOwnerPublicId($jws->getClaim('sub'));
        $id_token->setScope([]);
        $id_token->setAccessTokenHash($jws->hasClaim('at_hash') ? $jws->getClaim('at_hash') : null);
        $id_token->setAuthorizationCodeHash($jws->hasClaim('c_hash') ? $jws->getClaim('c_hash') : null);
        $id_token->setNonce($jws->hasClaim('nonce') ? $jws->getClaim('nonce') : null);

        return $id_token;
    }

    /**
     * @return \OAuth2\Token\IdTokenInterface
     */
    protected function createEmptyIdToken()
    {
        return new IdToken();
    }

    /**
     * @param \OAuth2\Client\ClientInterface $client Client
     *
     * @return int
     */
    private function getLifetime(ClientInterface $client)
    {
        $lifetime = $this->getConfiguration()->get('id_token_lifetime', 3600);
        if ($client instanceof TokenLifetimeExtensionInterface && is_int($_lifetime = $client->getTokenLifetime('id_token'))) {
            return $_lifetime;
        }

        return $lifetime;
    }

    /**
     * @throws \OAuth2\Exception\BaseExceptionInterface
     *
     * @return string
     */
    private function getSignatureAlgorithm()
    {
        $signature_algorithm = $this->getConfiguration()->get('id_token_signature_algorithm', null);
        if (!is_string($signature_algorithm)) {
            throw $this->getExceptionManager()->getException(ExceptionManagerInterface::INTERNAL_SERVER_ERROR, ExceptionManagerInterface::SERVER_ERROR, 'The signature algorithm used to sign ID tokens is not set.');
        }

        return $signature_algorithm;
    }
}
