<?php

declare(strict_types=1);

/*
 * The MIT License (MIT)
 *
 * Copyright (c) 2014-2017 Spomky-Labs
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file for details.
 */

namespace OAuth2\Endpoint\UserInfo;

use Assert\Assertion;
use Base64Url\Base64Url;
use Interop\Http\ServerMiddleware\DelegateInterface;
use Interop\Http\ServerMiddleware\MiddlewareInterface;
use Jose\JWTCreatorInterface;
use Jose\Object\JWKSetInterface;
use OAuth2\Model\AccessToken\AccessToken;
use OAuth2\Model\Client\Client;
use OAuth2\Model\Client\ClientRepositoryInterface;
use OAuth2\Model\UserAccount\UserAccount;
use OAuth2\Model\UserAccount\UserAccountId;
use OAuth2\Model\UserAccount\UserAccountRepositoryInterface;
use OAuth2\Response\OAuth2Exception;
use OAuth2\Response\OAuth2ResponseFactoryManagerInterface;
use Psr\Http\Message\ServerRequestInterface;

class UserInfoEndpoint implements MiddlewareInterface
{
    /**
     * @var string|null
     */
    private $signatureAlgorithm = null;

    /**
     * @var JWKSetInterface|null
     */
    private $signatureKeySet = null;

    /**
     * @var UserInfo
     */
    private $userinfo;

    /**
     * @var null|JWTCreatorInterface
     */
    private $jwtCreator = null;

    /**
     * @var null|string
     */
    private $issuer;

    /**
     * @var ClientRepositoryInterface
     */
    private $clientRepository;

    /**
     * @var UserAccountRepositoryInterface
     */
    private $userAccountRepository;

    /**
     * UserInfoEndpoint constructor.
     *
     * @param UserInfo                       $userinfo
     * @param ClientRepositoryInterface      $clientRepository
     * @param UserAccountRepositoryInterface $userAccountRepository
     */
    public function __construct(UserInfo $userinfo, ClientRepositoryInterface $clientRepository, UserAccountRepositoryInterface $userAccountRepository)
    {
        $this->userinfo = $userinfo;
        $this->clientRepository = $clientRepository;
        $this->userAccountRepository = $userAccountRepository;
    }

    /**
     * @param JWTCreatorInterface $jwtCreator
     * @param string              $issuer
     * @param string              $signatureAlgorithm
     * @param JWKSetInterface     $signatureKeySet
     */
    public function enableSignedResponsesSupport(JWTCreatorInterface $jwtCreator, string $issuer, string $signatureAlgorithm, JWKSetInterface $signatureKeySet)
    {
        Assertion::inArray($signatureAlgorithm, $jwtCreator->getSupportedSignatureAlgorithms());
        Assertion::greaterThan($signatureKeySet->countKeys(), 0, 'The signature key set must have at least one key.');
        $this->jwtCreator = $jwtCreator;
        $this->issuer = $issuer;
        $this->signatureKeySet = $signatureKeySet;
        $this->signatureAlgorithm = $signatureAlgorithm;
    }

    /**
     * @return bool
     */
    public function isSignedResponsesSupportEnabled(): bool
    {
        return null !== $this->jwtCreator;
    }

    /**
     * @return string[]
     */
    public function getSupportedSignatureAlgorithms(): array
    {
        return false === $this->isSignedResponsesSupportEnabled() ? [] : $this->jwtCreator->getSupportedSignatureAlgorithms();
    }

    /**
     * @return string[]
     */
    public function getSupportedKeyEncryptionAlgorithms(): array
    {
        return false === $this->isSignedResponsesSupportEnabled() ? [] : $this->jwtCreator->getSupportedKeyEncryptionAlgorithms();
    }

    /**
     * {@inheritdoc}
     */
    public function getSupportedContentEncryptionAlgorithms()
    {
        return false === $this->isSignedResponsesSupportEnabled() ? [] : $this->jwtCreator->getSupportedContentEncryptionAlgorithms();
    }

    public function process(ServerRequestInterface $request, DelegateInterface $delegate)
    {
        /**
         * @var AccessToken $accessToken
         */
        $accessToken = $request->getAttribute('access_token');

        $this->checkScope($accessToken);
        $this->checkRedirectUri($accessToken);

        $client = $this->getClient($accessToken);
        $user = $this->getUserAccount($accessToken);
        $endpoint_claims = $this->getEndpointClaims($accessToken);

        $claims = $this->userinfo->getUserinfo(
            $client,
            $user,
            $accessToken->getMetadata('redirect_uri'),
            $accessToken->hasMetadata('claims_locales') ? $accessToken->getMetadata('claims_locales') : null,
            $endpoint_claims,
            $accessToken->getScopes()
        );

        if (true === $this->isSignedResponsesSupportEnabled()) {
            $claims = array_merge(
                $claims,
                [
                    'jti'       => Base64Url::encode(random_bytes(25)),
                    'iss'       => $this->issuer,
                    'aud'       => [$this->issuer, $client->getId()],
                    'iat'       => time(),
                    'nbf'       => time(),
                    'exp'       => $accessToken->getExpiresAt(),
                ]
            );

            return $this->signAndEncrypt($claims, $client);
        }

        return $claims;
    }

    /**
     * @param AccessToken $accessToken
     *
     * @return array
     */
    private function getEndpointClaims(AccessToken $accessToken): array
    {
        if (!$accessToken->hasMetadata('requested_claims')) {
            return [];
        }

        $requested_claims = $accessToken->getMetadata('requested_claims');
        if (true === array_key_exists('userinfo', $requested_claims)) {
            return $requested_claims['userinfo'];
        }

        return [];
    }

    /**
     * @param AccessToken $accessToken
     *
     * @throws OAuth2Exception
     *
     * @return null|Client
     */
    private function getClient(AccessToken $accessToken): Client
    {
        $clientId = $accessToken->getClientId();
        if (null === $clientId || null === $client = $this->clientRepository->find($clientId)) {
            throw new OAuth2Exception(400, ['error' => OAuth2ResponseFactoryManagerInterface::ERROR_INVALID_REQUEST, 'error_description' => 'Unable to find the client.']);
        }

        return $client;
    }

    /**
     * @param AccessToken $accessToken
     *
     * @throws OAuth2Exception
     *
     * @return UserAccount
     */
    private function getUserAccount(AccessToken $accessToken): UserAccount
    {
        $userAccountId = $accessToken->getResourceOwnerId();
        if (!$userAccountId instanceof UserAccountId || null === $userAccount = $this->userAccountRepository->find($userAccountId)) {
            throw new OAuth2Exception(400, ['error' => OAuth2ResponseFactoryManagerInterface::ERROR_INVALID_REQUEST, 'error_description' => 'Unable to find the resource owner.']);
        }

        return $userAccount;
    }

    /**
     * @param array  $claims
     * @param Client $client
     *
     * @return string
     */
    private function signAndEncrypt(array $claims, Client $client): string
    {
        $signature_key = $this->signatureKeySet->getKey(0);
        Assertion::notNull($signature_key, 'Unable to find a key to sign the userinfo response. Please verify the selected key set contains suitable keys.');
        $jwt = $this->jwtCreator->sign(
            $claims,
            [
                'typ' => 'JWT',
                'alg' => $this->signatureAlgorithm,
            ],
            $signature_key
        );

        if ($client->hasPublicKeySet() && $client->has('id_token_encrypted_response_alg') && $client->has('id_token_encrypted_response_enc')) {
            $key_set = $client->getPublicKeySet();
            $key = $key_set->selectKey('enc');
            if (null !== $key) {
                $jwt = $this->jwtCreator->encrypt(
                    $jwt,
                    [
                        'alg' => $client->get('id_token_encrypted_response_alg'),
                        'enc' => $client->get('id_token_encrypted_response_enc'),
                    ],
                    $key
                );
            }
        }

        return $jwt;
    }

    /**
     * @param AccessToken $accessToken
     *
     * @throws OAuth2Exception
     */
    private function checkRedirectUri(AccessToken $accessToken)
    {
        if (!$accessToken->hasMetadata('redirect_uri')) {
            throw new OAuth2Exception(400, ['error' => OAuth2ResponseFactoryManagerInterface::ERROR_INVALID_REQUEST, 'error_description' => 'The access token has been issued through the authorization endpoint and cannot be used.']);
        }
    }

    /**
     * @param AccessToken $accessToken
     *
     * @throws OAuth2Exception
     */
    private function checkScope(AccessToken $accessToken)
    {
        if (!$accessToken->hasScope('openid')) {
            throw new OAuth2Exception(400, ['error' => OAuth2ResponseFactoryManagerInterface::ERROR_INVALID_REQUEST, 'error_description' => 'The access token does not contain the \'openid\' scope.']);
        }
    }
}
