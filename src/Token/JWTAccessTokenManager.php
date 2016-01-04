<?php

/*
 * The MIT License (MIT)
 *
 * Copyright (c) 2014-2015 Spomky-Labs
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file for details.
 */

namespace OAuth2\Token;

use OAuth2\Behaviour\HasExceptionManager;
use OAuth2\Behaviour\HasJWTEncrypter;
use OAuth2\Behaviour\HasJWTLoader;
use OAuth2\Behaviour\HasJWTSigner;
use OAuth2\Client\ClientInterface;
use OAuth2\Configuration\ConfigurationInterface;
use OAuth2\Exception\ExceptionManagerInterface;
use OAuth2\ResourceOwner\ResourceOwnerInterface;
use OAuth2\Util\JWTEncrypter;
use OAuth2\Util\JWTLoader;
use OAuth2\Util\JWTSigner;

abstract class JWTAccessTokenManager extends AccessTokenManager
{
    use HasExceptionManager;
    use HasJWTLoader;
    use HasJWTSigner;
    use HasJWTEncrypter;

    public function __construct(
        JWTLoader $jwt_loader,
        JWTSigner $jwt_signer,
        JWTEncrypter $jwt_encrypter,
        ExceptionManagerInterface $exception_manager,
        ConfigurationInterface $configuration,
        AccessTokenTypeManagerInterface $access_token_type_manager
    ) {
        parent::__construct($configuration, $access_token_type_manager);
        $this->setJWTLoader($jwt_loader);
        $this->setJWTSigner($jwt_signer);
        $this->setJWTEncrypter($jwt_encrypter);
        $this->setExceptionManager($exception_manager);
    }

    /**
     * @var array
     */
    protected $encryption_private_key = [];

    /**
     * @return array
     */
    public function getEncryptionPrivateKey()
    {
        return $this->encryption_private_key;
    }

    /**
     * @param array $encryption_private_key
     *
     * @return $this
     */
    public function setEncryptionPrivateKey(array $encryption_private_key)
    {
        $this->encryption_private_key = $encryption_private_key;
    }

    /**
     * {@inheritdoc}
     */
    public function populateAccessToken(AccessTokenInterface &$access_token, ClientInterface $client, ResourceOwnerInterface $resource_owner, RefreshTokenInterface $refresh_token = null)
    {
        $payload = $this->preparePayload($access_token);
        $signature_header = $this->prepareSignatureHeader();

        $jws = $this->getJWTSigner()->sign($payload, $signature_header);
        if (!is_string($jws)) {
            throw $this->getExceptionManager()->getException(ExceptionManagerInterface::INTERNAL_SERVER_ERROR, ExceptionManagerInterface::SERVER_ERROR, 'An error occured during the creation of the access token.');
        }
        $jwe = $this->encrypt($jws, $client);
        if (!is_string($jwe)) {
            throw $this->getExceptionManager()->getException(ExceptionManagerInterface::INTERNAL_SERVER_ERROR, ExceptionManagerInterface::SERVER_ERROR, 'An error occured during the creation of the access token.');
        }

        $access_token->setToken($jwe);
    }

    /**
     * @param \OAuth2\Client\ClientInterface $client
     *
     * @throws \OAuth2\Exception\BaseExceptionInterface
     *
     * @return array
     */
    protected function prepareEncryptionHeader(ClientInterface $client)
    {
        $key_encryption_algorithm = $this->getKeyEncryptionAlgorithm();
        $content_encryption_algorithm = $this->getContentEncryptionAlgorithm();
        $audience = $this->getConfiguration()->get('jwt_access_token_audience', null);
        $issuer = $this->getConfiguration()->get('jwt_access_token_issuer', null);

        if (!is_string($issuer)) {
            throw $this->getExceptionManager()->getException(ExceptionManagerInterface::INTERNAL_SERVER_ERROR, ExceptionManagerInterface::SERVER_ERROR, 'The configuration option "jwt_access_token_issuer" is not set.');
        }
        if (!is_string($key_encryption_algorithm)) {
            throw $this->getExceptionManager()->getException(ExceptionManagerInterface::INTERNAL_SERVER_ERROR, ExceptionManagerInterface::SERVER_ERROR, 'The configuration option "jwt_access_token_key_encryption_algorithm" is not set.');
        }
        if (!is_string($content_encryption_algorithm)) {
            throw $this->getExceptionManager()->getException(ExceptionManagerInterface::INTERNAL_SERVER_ERROR, ExceptionManagerInterface::SERVER_ERROR, 'The configuration option "jwt_access_token_content_encryption_algorithm" is not set.');
        }

        $header = array_merge(
            [
                'iss' => $issuer,
                'iat' => time(),
                'nbf' => time(),
                'exp' => time() + $this->getLifetime($client),
                'typ' => 'JWT',
                'alg' => $key_encryption_algorithm,
                'enc' => $content_encryption_algorithm,
            ]
        );
        if (null !== $audience) {
            $header['aud'] = $audience;
        }

        return $header;
    }

    /**
     * @throws \OAuth2\Exception\BaseExceptionInterface
     *
     * @return array
     */
    protected function prepareSignatureHeader()
    {
        $signature_algorithm = $this->getSignatureAlgorithm();
        if (!is_string($signature_algorithm)) {
            throw $this->getExceptionManager()->getException(ExceptionManagerInterface::INTERNAL_SERVER_ERROR, ExceptionManagerInterface::SERVER_ERROR, 'The configuration option "jwt_access_token_signature_algorithm" is not set.');
        }

        $header = [
            'typ' => 'JWT',
            'alg' => $signature_algorithm,
        ];

        $key = $this->getJWTSigner()->getSignatureKey();
        if ($key->has('kid')) {
            $header['kid'] = $key->get('kid');
        }

        return $header;
    }

    /**
     * @param \OAuth2\Token\AccessTokenInterface $access_token
     *
     * @throws \OAuth2\Exception\BaseExceptionInterface
     *
     * @return array
     */
    protected function preparePayload(AccessTokenInterface $access_token)
    {
        $audience = $this->getConfiguration()->get('jwt_access_token_audience', null);
        $issuer = $this->getConfiguration()->get('jwt_access_token_issuer', null);

        if (!is_string($issuer)) {
            throw $this->getExceptionManager()->getException(ExceptionManagerInterface::INTERNAL_SERVER_ERROR, ExceptionManagerInterface::SERVER_ERROR, 'The configuration option "jwt_access_token_issuer" is not set.');
        }

        $payload = [
            'iss' => $issuer,
            'iat' => time(),
            'nbf' => time(),
            'exp' => $access_token->getExpiresAt(),
            'sub' => $access_token->getClientPublicId(),
            'aty' => $access_token->getTokenType(),
            'sco' => $access_token->getScope(),
            'r_o' => $access_token->getResourceOwnerPublicId(),
        ];
        if (!empty($access_token->getParameters())) {
            $payload['oth'] = $access_token->getParameters();
        }
        if (null !== $audience) {
            $payload['aud'] = $audience;
        }
        if (null !== $access_token->getRefreshToken()) {
            $payload['ref'] = $access_token->getRefreshToken();
        }

        return $payload;
    }

    /**
     * @param string                         $payload
     * @param \OAuth2\Client\ClientInterface $client
     *
     * @throws \OAuth2\Exception\BaseExceptionInterface
     *
     * @return string
     */
    private function encrypt($payload, ClientInterface $client)
    {
        if (false === $this->getConfiguration()->get('jwt_access_token_encrypted', false)) {
            return $payload;
        }

        if (!$this->getJWTEncrypter() instanceof JWTEncrypter) {
            throw $this->getExceptionManager()->getException(ExceptionManagerInterface::INTERNAL_SERVER_ERROR, ExceptionManagerInterface::SERVER_ERROR, 'Encrypter is not defined.');
        }

        $header = $this->prepareEncryptionHeader($client);

        return $this->getJWTEncrypter()->encrypt($payload, $header, $this->getEncryptionPrivateKey());
    }

    /**
     * {@inheritdoc}
     */
    public function getAccessToken($assertion)
    {
        $jwt = $this->getJWTLoader()->load($assertion);

        $access_token = new JWTAccessToken();
        $access_token->setToken($assertion);
        $access_token->setJWS($jwt);
        $access_token->setClientPublicId($jwt->getClaim('sub'));
        $access_token->setExpiresAt($jwt->getClaim('exp'));
        $access_token->setTokenType($jwt->getClaim('aty'));
        $access_token->setResourceOwnerPublicId($jwt->getClaim('r_o'));

        if ($jwt->hasClaim('oth')) {
            $access_token->setParameters($jwt->getClaim('oth'));
        }
        if ($jwt->hasClaim('sco')) {
            $access_token->setScope($jwt->getClaim('sco'));
        }
        if ($jwt->hasClaim('ref')) {
            $access_token->setRefreshToken($jwt->getClaim('ref'));
        }

        return $access_token;
    }

    /**
     * {@inheritdoc}
     */
    public function revokeAccessToken(AccessTokenInterface $access_token)
    {
        //Not implemented
    }

    /**
     * @return string[]
     */
    protected function getRequiredClaims()
    {
        return [
            'iss',
            'aud',
            'sub',
            'exp',
        ];
    }

    /**
     * @throws \OAuth2\Exception\BaseExceptionInterface
     *
     * @return string
     */
    protected function getSignatureAlgorithm()
    {
        $signature_algorithm = $this->getConfiguration()->get('jwt_access_token_signature_algorithm', null);
        if (!is_string($signature_algorithm)) {
            throw $this->getExceptionManager()->getException(ExceptionManagerInterface::INTERNAL_SERVER_ERROR, ExceptionManagerInterface::SERVER_ERROR, 'The signature algorithm used to sign access tokens is not set.');
        }

        return $signature_algorithm;
    }

    /**
     * @throws \OAuth2\Exception\BaseExceptionInterface
     *
     * @return string
     */
    protected function getKeyEncryptionAlgorithm()
    {
        $key_encryption_algorithm = $this->getConfiguration()->get('jwt_access_token_key_encryption_algorithm', null);
        if (!is_string($key_encryption_algorithm)) {
            throw $this->getExceptionManager()->getException(ExceptionManagerInterface::INTERNAL_SERVER_ERROR, ExceptionManagerInterface::SERVER_ERROR, 'The key encryption algorithm used to encrypt access tokens is not set.');
        }

        return $key_encryption_algorithm;
    }

    /**
     * @throws \OAuth2\Exception\BaseExceptionInterface
     *
     * @return string
     */
    protected function getContentEncryptionAlgorithm()
    {
        $content_encryption_algorithm = $this->getConfiguration()->get('jwt_access_token_content_encryption_algorithm', null);
        if (!is_string($content_encryption_algorithm)) {
            throw $this->getExceptionManager()->getException(ExceptionManagerInterface::INTERNAL_SERVER_ERROR, ExceptionManagerInterface::SERVER_ERROR, 'The content encryption algorithm used to encrypt access tokens is not set.');
        }

        return $content_encryption_algorithm;
    }

    /**
     * {@inheritdoc}
     */
    protected function saveAccessToken(AccessTokenInterface $access_token)
    {
        // Nothing to do.
    }
}
