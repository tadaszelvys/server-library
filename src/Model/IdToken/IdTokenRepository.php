<?php

/*
 * The MIT License (MIT)
 *
 * Copyright (c) 2014-2016 Spomky-Labs
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file for details.
 */

namespace OAuth2\Model\IdToken;

use Assert\Assertion;
use Base64Url\Base64Url;
use Jose\JWTCreatorInterface;
use Jose\JWTLoaderInterface;
use Jose\Object\JWKSetInterface;
use OAuth2\OpenIdConnect\UserInfo\UserInfoInterface;

class IdTokenRepository implements IdTokenRepositoryInterface
{
    /**
     * @var int
     */
    private $idTokenLifetime = 3600;

    /**
     * @var string
     */
    private $signatureAlgorithm;

    /**
     * @var JWKSetInterface|null
     */
    private $signatureKeySet = null;

    /**
     * @var JWKSetInterface|null
     */
    private $encryptionKeySet = null;

    /**
     * @var UserInfoInterface
     */
    private $userinfo;

    /**
     * @var string
     */
    private $issuer;

    /**
     * @var JWTCreatorInterface
     */
    private $jwtCreator;

    /**
     * @var JWTLoaderInterface
     */
    private $jwtLoader;

    /**
     * IdTokenManager constructor.
     *
     * @param JWTCreatorInterface $jwtCreator
     * @param JWTLoaderInterface  $jwtLoader
     * @param string              $issuer
     * @param string              $signatureAlgorithm
     * @param JWKSetInterface     $signatureKeySet
     * @param UserInfoInterface   $userinfo
     */
    public function __construct(JWTCreatorInterface $jwtCreator, JWTLoaderInterface $jwtLoader, string $issuer, string $signatureAlgorithm, JWKSetInterface $signatureKeySet, UserInfoInterface $userinfo)
    {
        Assertion::greaterThan($signatureKeySet->countKeys(), 0, 'The signature key set must have at least one key.');
        $this->issuer = $issuer;
        $this->signatureAlgorithm = $signatureAlgorithm;
        $this->signatureKeySet = $signatureKeySet;
        $this->userinfo = $userinfo;
        $this->jwtCreator = $jwtCreator;
        $this->jwtLoader = $jwtLoader;
    }

    /**
     * {@inheritdoc}
     */
    public function enableEncryptionSupport(JWKSetInterface $encryptionKeySet)
    {
        Assertion::greaterThan($encryptionKeySet->countKeys(), 0, 'The encryption key set must have at least one key.');
        $this->encryptionKeySet = $encryptionKeySet;
    }

    /**
     * {@inheritdoc}
     */
    public function getPublicIdFromSubjectIdentifier($subject_identifier)
    {
        $algorithm = $this->userinfo->getPairwiseSubjectIdentifierAlgorithm();
        if (null === $algorithm) {
            return $subject_identifier;
        }

        return $algorithm->getPublicIdFromSubjectIdentifier($subject_identifier);
    }

    /**
     * {@inheritdoc}
     */
    public function getSupportedSignatureAlgorithms()
    {
        return $this->jwtCreator->getSupportedSignatureAlgorithms();
    }

    /**
     * {@inheritdoc}
     */
    public function getSupportedKeyEncryptionAlgorithms()
    {
        return $this->jwtCreator->getSupportedKeyEncryptionAlgorithms();
    }

    /**
     * {@inheritdoc}
     */
    public function getSupportedContentEncryptionAlgorithms()
    {
        return $this->jwtCreator->getSupportedContentEncryptionAlgorithms();
    }

    /**
     * {@inheritdoc}
     */
    public function createIdToken(ClientInterface $client, UserAccountInterface $user_account, $redirect_uri, $claims_locales, array $request_claims, array $scope, array $id_token_claims = [], AccessTokenInterface $access_token = null, AuthCodeInterface $auth_code = null)
    {
        $id_token = $this->createEmptyIdToken();
        $exp = null !== $access_token ? $access_token->getExpiresAt() : time() + $this->getLifetime($client);
        $claims = array_merge(
            $this->userinfo->getUserinfo($client, $user_account, $redirect_uri, $claims_locales, $request_claims, $scope),
            [
                'jti'       => Base64Url::encode(random_bytes(25)),
                'iss'       => $this->getIssuer(),
                'aud'       => [$client->getPublicId(), $this->getIssuer()],
                'iat'       => time(),
                'nbf'       => time(),
                'exp'       => $exp,
            ]
        );

        foreach (['at_hash' => $access_token, 'c_hash' => $auth_code] as $key => $token) {
            if (null !== $token) {
                $claims[$key] = $this->getHash($token->getToken());
            }
        }

        foreach (['last_login_at' => 'auth_time', 'amr' => 'amr', 'acr' => 'acr'] as $claim => $key) {
            if ($user_account->has($claim)) {
                $claims[$key] = $user_account->get($claim);
            }
        }

        $headers = [
            'typ'       => 'JWT',
            'alg'       => $this->getSignatureAlgorithm(),
        ];
        $signature_key = $this->signatureKeySet->selectKey('sig', $this->getSignatureAlgorithm());
        Assertion::notNull($signature_key, 'Unable to find a key to sign the ID Token. Please verify the selected key set contains suitable keys.');
        if ($signature_key->has('kid')) {
            $headers['kid'] = $signature_key->get('kid');
        }

        if (!empty($id_token_claims)) {
            $claims = array_merge($claims, $id_token_claims);
        }

        $jwt = $this->jwtCreator->sign($claims, $headers, $signature_key);

        if ($client->hasPublicKeySet() && $client->has('id_token_encrypted_response_alg') && $client->has('id_token_encrypted_response_enc')) {
            $key_set = $client->getPublicKeySet();
            $key = $key_set->selectKey('enc');
            if (null !== $key) {
                $headers = [
                    'typ'       => 'JWT',
                    'jti'       => Base64Url::encode(random_bytes(25)),
                    'alg'       => $client->get('id_token_encrypted_response_alg'),
                    'enc'       => $client->get('id_token_encrypted_response_enc'),
                ];

                $jwt = $this->jwtCreator->encrypt($jwt, $headers, $key);
            }
        }
        $id_token->setToken($jwt);

        $id_token->setExpiresAt($exp);
        $id_token->setClientPublicId($client->getPublicId());
        $id_token->setResourceOwnerPublicId($user_account->getUserPublicId());

        return $id_token;
    }

    /**
     * {@inheritdoc}
     */
    public function loadIdToken($id_token)
    {
        try {
            $jwt = $this->jwtLoader->load($id_token, $this->encryptionKeySet, false);

            $this->jwtLoader->verify($jwt, $this->signatureKeySet);
        } catch (\Exception $e) {
            return;
        }

        return $jwt;
    }

    /**
     * {@inheritdoc}
     */
    public function revokeIdToken(IdToken $token)
    {
        //Not supported
    }

    /**
     * @param Token $token
     *
     * @return string
     */
    private function getHash(Token $token): string
    {
        return Base64Url::encode(mb_substr(hash($this->getHashMethod(), $token->getValue(), true), 0, $this->getHashSize(), '8bit'));
    }

    /**
     * @throws \InvalidArgumentException
     *
     * @return string
     */
    private function getHashMethod(): string
    {
        $map = [
            'HS256' => 'sha256',
            'ES256' => 'sha256',
            'RS256' => 'sha256',
            'PS256' => 'sha256',
            'HS384' => 'sha384',
            'ES384' => 'sha384',
            'RS384' => 'sha384',
            'PS384' => 'sha384',
            'HS512' => 'sha512',
            'ES512' => 'sha512',
            'RS512' => 'sha512',
            'PS512' => 'sha512',
        ];

        if (array_key_exists($this->signatureAlgorithm, $map)) {
            return $map[$this->signatureAlgorithm];
        }

        throw new \InvalidArgumentException(sprintf('Algorithm \'%s\' is not supported', $this->signatureAlgorithm));
    }

    /**
     * @throws \InvalidArgumentException
     *
     * @return int
     */
    private function getHashSize(): int
    {
        $map = [
            'HS256' => 16,
            'ES256' => 16,
            'RS256' => 16,
            'PS256' => 16,
            'HS384' => 24,
            'ES384' => 24,
            'RS384' => 24,
            'PS384' => 24,
            'HS512' => 32,
            'ES512' => 32,
            'RS512' => 32,
            'PS512' => 32,
        ];

        Assertion::keyExists($map, $this->signatureAlgorithm, sprintf('Algorithm \'%s\' is not supported', $this->signatureAlgorithm));

        return $map[$this->signatureAlgorithm];
    }

    /**
     * @return string
     */
    private function getSignatureAlgorithm(): string
    {
        return $this->signatureAlgorithm;
    }

    /**
     * @return int
     */
    public function getIdTokenLifetime(): int
    {
        return $this->idTokenLifetime;
    }

    /**
     * @param int $idTokenLifetime
     */
    public function setIdTokenLifetime(int $idTokenLifetime)
    {
        Assertion::greaterThan($idTokenLifetime, 0);
        $this->idTokenLifetime = $idTokenLifetime;
    }
}
