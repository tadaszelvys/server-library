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
use Jose\Object\JWKInterface;
use OAuth2\Behaviour\HasExceptionManager;
use OAuth2\Behaviour\HasJWTEncrypter;
use OAuth2\Behaviour\HasJWTLoader;
use OAuth2\Behaviour\HasJWTSigner;
use OAuth2\Client\ClientInterface;
use OAuth2\Exception\ExceptionManagerInterface;
use OAuth2\ResourceOwner\ResourceOwnerInterface;
use OAuth2\Util\JWTEncrypter;
use OAuth2\Util\JWTLoader;
use OAuth2\Util\JWTSigner;

class JWTAccessTokenManager extends AccessTokenManager
{
    use HasExceptionManager;
    use HasJWTLoader;
    use HasJWTSigner;
    use HasJWTEncrypter;

    /**
     * @var string
     */
    private $issuer;

    /**
     * @var string
     */
    private $audience;

    /**
     * @var string
     */
    private $signature_algorithm;

    /**
     * @var bool
     */
    private $encrypted_access_token;

    /**
     * @var null|string
     */
    private $key_encryption_algorithm;

    /**
     * @var null|string
     */
    private $content_encryption_algorithm;

    /**
     * JWTAccessTokenManager constructor.
     *
     * @param \OAuth2\Util\JWTLoader                      $jwt_loader
     * @param \OAuth2\Util\JWTSigner                      $jwt_signer
     * @param \OAuth2\Util\JWTEncrypter                   $jwt_encrypter
     * @param \OAuth2\Exception\ExceptionManagerInterface $exception_manager
     * @param string                                      $issuer
     * @param string                                      $audience
     * @param string                                      $signature_algorithm
     * @param bool                                        $encrypted_access_token
     * @param null|string                                 $key_encryption_algorithm
     * @param null|string                                 $content_encryption_algorithm
     */
    public function __construct(
        JWTLoader $jwt_loader,
        JWTSigner $jwt_signer,
        JWTEncrypter $jwt_encrypter,
        ExceptionManagerInterface $exception_manager,
        $issuer,
        $audience,
        $signature_algorithm,
        $encrypted_access_token = false,
        $key_encryption_algorithm = null,
        $content_encryption_algorithm = null
    ) {
        Assertion::string($issuer);
        Assertion::string($audience);
        Assertion::string($signature_algorithm);
        Assertion::boolean($encrypted_access_token);
        Assertion::nullOrString($key_encryption_algorithm);
        Assertion::nullOrString($content_encryption_algorithm);

        $this->setJWTLoader($jwt_loader);
        $this->setJWTSigner($jwt_signer);
        $this->setJWTEncrypter($jwt_encrypter);
        $this->setExceptionManager($exception_manager);
        $this->issuer = $issuer;
        $this->audience = $audience;
        $this->signature_algorithm = $signature_algorithm;
        $this->encrypted_access_token = $encrypted_access_token;
        $this->key_encryption_algorithm = $key_encryption_algorithm;
        $this->content_encryption_algorithm = $content_encryption_algorithm;
    }

    /**
     * @var null|\Jose\Object\JWKSetInterface
     */
    private $encryption_private_key;

    /**
     * @return null|\Jose\Object\JWKSetInterface
     */
    public function getEncryptionPrivateKey()
    {
        return $this->encryption_private_key;
    }

    /**
     * @param \Jose\Object\JWKInterface $encryption_private_key
     *
     * @return $this
     */
    public function setEncryptionPrivateKey(JWKInterface $encryption_private_key)
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

        $header = array_merge(
            [
                'iss' => $this->issuer,
                'iat' => time(),
                'nbf' => time(),
                'exp' => time() + $this->getLifetime($client),
                'typ' => 'JWT',
                'alg' => $key_encryption_algorithm,
                'enc' => $content_encryption_algorithm,
            ]
        );
        if (null !== $this->audience) {
            $header['aud'] = $this->audience;
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
        $payload = [
            'iss' => $this->issuer,
            'iat' => time(),
            'nbf' => time(),
            'exp' => $access_token->getExpiresAt(),
            'sub' => $access_token->getClientPublicId(),
            'aty' => $access_token->getTokenType(),
            'sco' => $access_token->getScope(),
            'r_o' => $access_token->getResourceOwnerPublicId(),
        ];
        if (!empty($access_token->getParameters())) {
            $parameters = $access_token->getParameters();
            //This part should be updated to support 'cnf' (confirmation) claim (see POP).

            $payload['oth'] = $parameters;
        }
        if (null !== $this->audience) {
            $payload['aud'] = $this->audience;
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
        if (false === $this->encrypted_access_token) {
            return $payload;
        }

        $key = $this->getEncryptionPrivateKey();

        if (!$key instanceof JWKInterface) {
            throw $this->getExceptionManager()->getException(ExceptionManagerInterface::INTERNAL_SERVER_ERROR, ExceptionManagerInterface::SERVER_ERROR, 'Encryption is enabled but encryption key is not set.');
        }
        if (!$this->getJWTEncrypter() instanceof JWTEncrypter) {
            throw $this->getExceptionManager()->getException(ExceptionManagerInterface::INTERNAL_SERVER_ERROR, ExceptionManagerInterface::SERVER_ERROR, 'Encrypter is not defined.');
        }

        $header = $this->prepareEncryptionHeader($client);

        return $this->getJWTEncrypter()->encrypt($payload, $header, $key);
    }

    /**
     * {@inheritdoc}
     */
    public function getAccessToken($assertion)
    {
        try {
            $jwt = $this->getJWTLoader()->load($assertion);
        } catch (\Exception $e) {
            return;
        }

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
        if ($jwt->hasClaim('cnf')) {
            $access_token->setParameter('cnf', $jwt->getClaim('cnf'));
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
     * @throws \OAuth2\Exception\BaseExceptionInterface
     *
     * @return string
     */
    protected function getSignatureAlgorithm()
    {
        if (!is_string($this->signature_algorithm)) {
            throw $this->getExceptionManager()->getException(ExceptionManagerInterface::INTERNAL_SERVER_ERROR, ExceptionManagerInterface::SERVER_ERROR, 'The signature algorithm used to sign access tokens is not set.');
        }

        return $this->signature_algorithm;
    }

    /**
     * @throws \OAuth2\Exception\BaseExceptionInterface
     *
     * @return string
     */
    protected function getKeyEncryptionAlgorithm()
    {
        if (!is_string($this->key_encryption_algorithm)) {
            throw $this->getExceptionManager()->getException(ExceptionManagerInterface::INTERNAL_SERVER_ERROR, ExceptionManagerInterface::SERVER_ERROR, 'The key encryption algorithm used to encrypt access tokens is not set.');
        }

        return $this->key_encryption_algorithm;
    }

    /**
     * @throws \OAuth2\Exception\BaseExceptionInterface
     *
     * @return string
     */
    protected function getContentEncryptionAlgorithm()
    {
        if (!is_string($this->content_encryption_algorithm)) {
            throw $this->getExceptionManager()->getException(ExceptionManagerInterface::INTERNAL_SERVER_ERROR, ExceptionManagerInterface::SERVER_ERROR, 'The content encryption algorithm used to encrypt access tokens is not set.');
        }

        return $this->content_encryption_algorithm;
    }

    /**
     * {@inheritdoc}
     */
    protected function saveAccessToken(AccessTokenInterface $access_token)
    {
        // Nothing to do.
    }
}
