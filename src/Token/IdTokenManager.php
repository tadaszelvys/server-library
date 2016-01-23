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

use Base64Url\Base64Url;
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

class  IdTokenManager implements IdTokenManagerInterface
{
    use HasExceptionManager;
    use HasConfiguration;
    use HasJWTLoader;
    use HasJWTSigner;

    /**
     * IdTokenManager constructor.
     *
     * @param \OAuth2\Util\JWTLoader                       $loader
     * @param \OAuth2\Util\JWTSigner                       $signer
     * @param \OAuth2\Exception\ExceptionManagerInterface  $exception_manager
     * @param \OAuth2\Configuration\ConfigurationInterface $configuration
     */
    public function __construct(JWTLoader $loader,
                                JWTSigner $signer,
                                ExceptionManagerInterface $exception_manager,
                                ConfigurationInterface $configuration
    ) {
        $this->setJWTLoader($loader);
        $this->setJWTSigner($signer);
        $this->setExceptionManager($exception_manager);
        $this->setConfiguration($configuration);
    }

    /**
     * {@inheritdoc}
     */
    public function createIdToken(ClientInterface $client, EndUserInterface $end_user, array $token_type_information, array $id_token_claims = [], AccessTokenInterface $access_token = null, AuthCodeInterface $auth_code = null)
    {
        $id_token = $this->createEmptyIdToken();
        $exp = time() + $this->getLifetime($client);

        $headers = [
            'typ'       => 'JWT',
            'alg'       => $this->getSignatureAlgorithm(),
        ];

        $payload = [
            'iss'       => $this->getConfiguration()->get('id_token_issuer', 'IdToken Server'),
            'sub'       => $end_user->getPublicId(),
            'aud'       => $client->getPublicId(),
            'iat'       => time(),
            'nbf'       => time(),
            'exp'       => $exp,
            'auth_time' => $end_user->getLastLoginAt(),
        ];

        if (null !== $access_token) {
            $payload['at_hash'] = $this->getHash($access_token);
        }
        if (null !== $auth_code) {
            $payload['c_hash'] = $this->getHash($auth_code);
        }
        if (!empty($id_token_claims)) {
            $payload = array_merge($payload, $id_token_claims);
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
    public function getIdToken($id_token)
    {
        $jws = $this->getJWTLoader()->load($id_token);
        //$this->getJWTLoader()->verifySignature($jws, );

        $id_token = $this->createEmptyIdToken();
        $id_token->setToken($id_token);
        $id_token->setJWS($jws);
        $id_token->setExpiresAt($jws->getClaim('exp'));
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
     * @param \OAuth2\Token\IdTokenInterface $is_token
     */
    protected function saveIdToken(IdTokenInterface $is_token)
    {
        //Nothing to do
    }

    /**
     * @param \OAuth2\Token\TokenInterface $token
     *
     * @return string
     */
    private function getHash(TokenInterface $token)
    {
        $signature_algorithm = $this->getConfiguration()->get('id_token_signature_algorithm', null);

        return substr(
            Base64Url::encode(hash(
                $this->getHashMethod($signature_algorithm),
                $token->getToken(),
                true
            )),
            0,
            $this->getHashSize($signature_algorithm)
        );
    }

    private function getHashMethod($id_token_signature_alogrithm)
    {
        switch ($id_token_signature_alogrithm) {
            case 'HS256':
            case 'ES256':
            case 'RS256':
            case 'PS256':
                return 'sha256';
            case 'HS384':
            case 'ES384':
            case 'RS384':
            case 'PS384':
                return 'sha384';
            case 'HS512':
            case 'ES512':
            case 'RS512':
            case 'PS512':
                return 'sha512';
            default:
                throw $this->getExceptionManager()->getException(
                    ExceptionManagerInterface::INTERNAL_SERVER_ERROR,
                    '',
                    ''
                );
        }
    }

    private function getHashSize($id_token_signature_alogrithm)
    {
        switch ($id_token_signature_alogrithm) {
            case 'HS256':
            case 'ES256':
            case 'RS256':
            case 'PS256':
                return 128;
            case 'HS384':
            case 'ES384':
            case 'RS384':
            case 'PS384':
                return 192;
            case 'HS512':
            case 'ES512':
            case 'RS512':
            case 'PS512':
                return 256;
            default:
                throw $this->getExceptionManager()->getException(
                    ExceptionManagerInterface::INTERNAL_SERVER_ERROR,
                    '',
                    ''
                );
        }
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
