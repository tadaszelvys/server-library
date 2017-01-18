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
use OAuth2\Model\UserAccount\UserAccount;
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
     * @var UserInfoInterface
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
     * UserInfoEndpoint constructor.
     *
     * @param UserInfoInterface $userinfo
     */
    public function __construct(UserInfoInterface $userinfo)
    {
        $this->userinfo = $userinfo;
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
     * @return \string[]
     */
    public function getSupportedSignatureAlgorithms(): array
    {
        return false === $this->isSignedResponsesSupportEnabled() ? [] : $this->jwtCreator->getSupportedSignatureAlgorithms();
    }

    /**
     * @return \string[]
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
        $access_token = $request->getAttribute('access_token');

        $this->checkScope($access_token->getScope());
        $this->checkHasRedirectUri($access_token);

        $client = $this->getClient($access_token);
        $user = $this->getUserAccount($access_token);
        $endpoint_claims = $this->getEndpointClaims($access_token);

        $claims = $this->userinfo->getUserinfo(
            $client,
            $user,
            $access_token->getMetadata('redirect_uri'),
            $access_token->hasMetadata('claims_locales') ? $access_token->getMetadata('claims_locales') : null,
            $endpoint_claims,
            $access_token->getScope()
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
                    'exp'       => $access_token->getExpiresAt(),
                ]
            );

            return $this->signAndEncrypt($claims, $client);
        }

        return $claims;
    }

    /**
     * @param AccessToken $access_token
     *
     * @return array
     */
    private function getEndpointClaims(AccessToken $access_token): array
    {
        if (!$access_token->hasMetadata('requested_claims')) {
            return [];
        }

        $requested_claims = $access_token->getMetadata('requested_claims');
        if (true === array_key_exists('userinfo', $requested_claims)) {
            return $requested_claims['userinfo'];
        }

        return [];
    }

    /**
     * @param AccessToken $access_token
     *
     * @throws OAuth2Exception
     *
     * @return null|Client
     */
    private function getClient(AccessToken $access_token): Client
    {
        $client = $access_token->getClient();
        if (null === $client) {
            throw new OAuth2Exception(400, ['error' => OAuth2ResponseFactoryManagerInterface::ERROR_INVALID_REQUEST, 'error_description' => 'Unable to find the client.']);
        }

        return $client;
    }

    /**
     * @param AccessToken $access_token
     *
     * @throws OAuth2Exception
     *
     * @return UserAccount
     */
    private function getUserAccount(AccessToken $access_token): UserAccount
    {
        $userAccount = $access_token->getResourceOwner();
        if (!$userAccount instanceof UserAccount) {
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
     * @param AccessToken $access_token
     *
     * @throws OAuth2Exception
     */
    private function checkHasRedirectUri(AccessToken $access_token)
    {
        if (!$access_token->hasMetadata('redirect_uri')) {
            throw new OAuth2Exception(400, ['error' => OAuth2ResponseFactoryManagerInterface::ERROR_INVALID_REQUEST, 'error_description' => 'The access token has been issued through the authorization endpoint and cannot be used.']);
        }
    }

    /**
     * @param string[] $scope
     *
     * @throws OAuth2Exception
     */
    private function checkScope(array $scope)
    {
        if (!in_array('openid', $scope)) {
            throw new OAuth2Exception(400, ['error' => OAuth2ResponseFactoryManagerInterface::ERROR_INVALID_REQUEST, 'error_description' => 'The access token does not contain the \'openid\' scope.']);
        }
    }
}
