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

use Assert\Assertion;
use Base64Url\Base64Url;
use OAuth2\Behaviour\HasJWTLoader;
use OAuth2\Behaviour\HasJWTSigner;
use OAuth2\Client\ClientInterface;
use OAuth2\Client\TokenLifetimeExtensionInterface;
use OAuth2\EndUser\EndUserInterface;
use OAuth2\Util\JWTLoader;
use OAuth2\Util\JWTSigner;

class IdTokenManager implements IdTokenManagerInterface
{
    use HasJWTLoader;
    use HasJWTSigner;

    /**
     * @var int
     */
    private $id_token_lifetime = 3600;

    /**
     * @var string
     */
    private $issuer;

    /**
     * @var string
     */
    private $signature_algorithm;

    /**
     * IdTokenManager constructor.
     *
     * @param \OAuth2\Util\JWTLoader                       $loader
     * @param \OAuth2\Util\JWTSigner                       $signer
     * @param string                                       $issuer
     * @param string                                       $signature_algorithm
     */
    public function __construct(JWTLoader $loader,
                                JWTSigner $signer,
                                $issuer,
                                $signature_algorithm
    ) {
        Assertion::string($issuer);
        Assertion::string($signature_algorithm);
        $this->issuer = $issuer;
        $this->signature_algorithm = $signature_algorithm;
        $this->setJWTLoader($loader);
        $this->setJWTSigner($signer);
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
            'iss'       => $this->issuer,
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

        $token = $this->createEmptyIdToken();
        $token->setToken($id_token);
        $token->setJWS($jws);
        $token->setExpiresAt($jws->getClaim('exp'));
        $token->setClientPublicId($jws->getClaim('aud'));
        $token->setResourceOwnerPublicId($jws->getClaim('sub'));
        $token->setScope([]);
        $token->setAccessTokenHash($jws->hasClaim('at_hash') ? $jws->getClaim('at_hash') : null);
        $token->setAuthorizationCodeHash($jws->hasClaim('c_hash') ? $jws->getClaim('c_hash') : null);
        $token->setNonce($jws->hasClaim('nonce') ? $jws->getClaim('nonce') : null);

        return $token;
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
        return substr(
            Base64Url::encode(hash(
                $this->getHashMethod(),
                $token->getToken(),
                true
            )),
            0,
            $this->getHashSize()
        );
    }

    /**
     * @return string
     *
     * @throws \OAuth2\Exception\BaseExceptionInterface
     */
    private function getHashMethod()
    {
        switch ($this->signature_algorithm) {
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
                throw new \InvalidArgumentException(sprintf('Algorithm "%s" is not supported', $this->signature_algorithm));
        }
    }

    /**
     * @return int
     *
     * @throws \OAuth2\Exception\BaseExceptionInterface
     */
    private function getHashSize()
    {
        switch ($this->signature_algorithm) {
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
                throw new \InvalidArgumentException(sprintf('Algorithm "%s" is not supported', $this->signature_algorithm));
        }
    }

    /**
     * @param \OAuth2\Client\ClientInterface $client Client
     *
     * @return int
     */
    private function getLifetime(ClientInterface $client)
    {
        $lifetime = $this->getIdTokenLifetime();
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
        return $this->signature_algorithm;
    }

    /**
     * @return int
     */
    public function getIdTokenLifetime()
    {
        return $this->id_token_lifetime;
    }

    /**
     * @param int $id_token_lifetime
     */
    public function setIdTokenLifetime($id_token_lifetime)
    {
        Assertion::integer($id_token_lifetime);
        $this->$id_token_lifetime = $id_token_lifetime;
    }
}
