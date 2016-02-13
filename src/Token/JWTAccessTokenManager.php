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
use Jose\ClaimChecker\ClaimCheckerManager;
use Jose\Factory\DecrypterFactory;
use Jose\Factory\VerifierFactory;
use Jose\Object\JWKInterface;
use Jose\Object\JWKSet;
use OAuth2\Behaviour\HasExceptionManager;
use OAuth2\Behaviour\HasJWTCreator;
use OAuth2\Behaviour\HasJWTLoader;
use OAuth2\Client\ClientInterface;
use OAuth2\Exception\ExceptionManagerInterface;
use OAuth2\ResourceOwner\ResourceOwnerInterface;
use OAuth2\ResourceServer\ResourceServerInterface;
use OAuth2\Util\JWTCreator;
use OAuth2\Util\JWTLoader;

class JWTAccessTokenManager extends AccessTokenManager
{
    use HasExceptionManager;
    use HasJWTLoader;
    use HasJWTCreator;

    /**
     * @var string
     */
    private $issuer;

    /**
     * JWTAccessTokenManager constructor.
     *
     * @param \OAuth2\Exception\ExceptionManagerInterface $exception_manager
     * @param string                                      $signature_algorithm
     * @param \Jose\Object\JWKInterface                   $signature_key
     * @param string                                      $key_encryption_algorithm
     * @param string                                      $content_encryption_algorithm
     * @param \Jose\Object\JWKInterface                   $key_encryption_key
     * @param string                                      $issuer
     */
    public function __construct(ExceptionManagerInterface $exception_manager,
                                $signature_algorithm,
                                JWKInterface $signature_key,
                                $key_encryption_algorithm,
                                $content_encryption_algorithm,
                                JWKInterface $key_encryption_key,
                                $issuer
    ) {
        Assertion::string($signature_algorithm);
        Assertion::string($key_encryption_algorithm);
        Assertion::string($content_encryption_algorithm);
        Assertion::string($issuer);

        $this->issuer = $issuer;

        $key_set = new JWKSet();
        $key_set = $key_set->addKey($signature_key);
        $key_set = $key_set->addKey($key_encryption_key);

        $this->setJWTLoader(new JWTLoader(
            new ClaimCheckerManager(),
            VerifierFactory::createVerifier([$signature_algorithm]),
            DecrypterFactory::createDecrypter([$key_encryption_algorithm, $content_encryption_algorithm]),
            $exception_manager,
            $key_set,
            true
        ));
        $this->setJWTCreator(new JWTCreator(
            $signature_algorithm,
            $signature_key,
            $key_encryption_algorithm,
            $content_encryption_algorithm,
            $key_encryption_key
        ));
    }

    /**
     * {@inheritdoc}
     */
    public function populateAccessToken(AccessTokenInterface &$access_token, ClientInterface $client, ResourceOwnerInterface $resource_owner, RefreshTokenInterface $refresh_token = null, ResourceServerInterface $resource_server = null)
    {
        $payload = $this->preparePayload($access_token, $resource_server);
        $signature_header = $this->prepareSignatureHeader();
        $encryption_header = $this->prepareEncryptionHeader($client, $resource_server);
        $recipient_key = null === $resource_server || null === $resource_server->getPublicKeyEncryptionKey() ? $this->getJWTCreator()->getSenderKey() : $resource_server->getPublicKeyEncryptionKey();

        $jwt = $this->getJWTCreator()->createJWT($payload, $signature_header, true, $encryption_header, $recipient_key);

        $access_token->setToken($jwt);
    }

    /**
     * @param \OAuth2\Client\ClientInterface                      $client
     * @param \OAuth2\ResourceServer\ResourceServerInterface|null $resource_server
     *
     * @return array
     */
    protected function prepareEncryptionHeader(ClientInterface $client, ResourceServerInterface $resource_server = null)
    {
        $key_encryption_algorithm = $this->getJWTCreator()->getKeyEncryptionAlgorithm();
        $content_encryption_algorithm = $this->getJWTCreator()->getContentEncryptionAlgorithm();

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
        $header['aud'] = null === $resource_server ? $this->issuer : $resource_server->getServerName();

        return $header;
    }

    /**
     * @throws \OAuth2\Exception\BaseExceptionInterface
     *
     * @return array
     */
    protected function prepareSignatureHeader()
    {
        $signature_algorithm = $this->getJWTCreator()->getSignatureAlgorithm();

        $header = [
            'typ' => 'JWT',
            'alg' => $signature_algorithm,
        ];

        return $header;
    }

    /**
     * @param \OAuth2\Token\AccessTokenInterface                  $access_token
     * @param \OAuth2\ResourceServer\ResourceServerInterface|null $resource_server
     *
     * @return array
     */
    protected function preparePayload(AccessTokenInterface $access_token, ResourceServerInterface $resource_server = null)
    {
        $payload = [
            'iss' => $this->issuer,
            'aud' => null === $resource_server ? $this->issuer : $resource_server->getServerName(),
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
        if (null !== $access_token->getRefreshToken()) {
            $payload['ref'] = $access_token->getRefreshToken();
        }

        return $payload;
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
     * {@inheritdoc}
     */
    protected function saveAccessToken(AccessTokenInterface $access_token)
    {
        // Nothing to do.
    }
}
