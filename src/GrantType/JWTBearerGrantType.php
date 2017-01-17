<?php

/*
 * The MIT License (MIT)
 *
 * Copyright (c) 2014-2016 Spomky-Labs
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file for details.
 */

namespace OAuth2\GrantType;

use Assert\Assertion;
use Jose\JWTLoaderInterface;
use Jose\Object\JWKSetInterface;
use Jose\Object\JWSInterface;
use OAuth2\Endpoint\Token\GrantTypeData;
use OAuth2\Model\Client\ClientId;
use OAuth2\Model\Client\ClientRepositoryInterface;
use OAuth2\Response\OAuth2Exception;
use OAuth2\Response\OAuth2ResponseFactoryManagerInterface;
use Psr\Http\Message\ServerRequestInterface;

class JWTBearerGrantType implements GrantTypeInterface
{
    /**
     * @var JWTLoaderInterface
     */
    private $jwtLoader;

    /**
     * @var ClientRepositoryInterface
     */
    private $clientRepository;

    /**
     * @var bool
     */
    private $encryptionRequired = false;

    /**
     * @var JWKSetInterface|null
     */
    private $keyEncryptionkeySet = null;

    /**
     * @var bool
     */
    private $issueRefreshToken = false;

    /**
     * JWTBearerGrantType constructor.
     *
     * @param JWTLoaderInterface $jwtLoader
     * @param ClientRepositoryInterface $clientRepository
     */
    public function __construct(JWTLoaderInterface $jwtLoader, ClientRepositoryInterface $clientRepository)
    {
        $this->jwtLoader = $jwtLoader;
        $this->clientRepository = $clientRepository;
    }

    /**
     * {@inheritdoc}
     */
    public function getAssociatedResponseTypes(): array
    {
        return [];
    }

    /**
     * @param bool            $encryptionRequired
     * @param JWKSetInterface $keyEncryptionkeySet
     */
    public function enableEncryptedAssertions($encryptionRequired,
                                              JWKSetInterface $keyEncryptionkeySet)
    {
        Assertion::boolean($encryptionRequired);

        $this->encryptionRequired = $encryptionRequired;
        $this->keyEncryptionkeySet = $keyEncryptionkeySet;
    }

    /**
     * {@inheritdoc}
     */
    public function getGrantType(): string
    {
        return 'urn:ietf:params:oauth:grant-type:jwt-bearer';
    }

    public function checkTokenRequest(ServerRequestInterface $request)
    {
        $parameters = $request->getParsedBody() ?? [];
        $requiredParameters = ['assertion'];

        foreach ($requiredParameters as $requiredParameter) {
            if (!array_key_exists($requiredParameter, $parameters)) {
                throw new OAuth2Exception(400, ['error' => OAuth2ResponseFactoryManagerInterface::ERROR_INVALID_REQUEST, 'error_description' => sprintf('The parameter \'%s\' is missing.', $requiredParameter)]);
            }
        }
    }

    /**
     * {@inheritdoc}
     */
    public function prepareTokenResponse(ServerRequestInterface $request, GrantTypeData $grantTypeResponse): GrantTypeData
    {
        $parameters = $request->getParsedBody() ?? [];
        $assertion = $parameters['assertion'];
        try {
            $jwt = $this->jwtLoader->load(
                $assertion,
                $this->keyEncryptionkeySet,
                $this->encryptionRequired
            );
            Assertion::isInstanceOf($jwt, JWSInterface::class, 'Assertion does not contain signed claims.');
            Assertion::true($jwt->hasClaim('sub'), 'Assertion does not contain \'sub\' claims.');
        } catch (\Exception $e) {
            throw new OAuth2Exception(
                400,
                [
                    'error'             => OAuth2ResponseFactoryManagerInterface::ERROR_INVALID_REQUEST,
                    'error_description' => $e->getMessage(),
                ]
            );
        }

        $client = $this->clientRepository->find(ClientId::create($jwt->getClaim('sub')));
        if (null === $client) {
            throw new  OAuth2Exception(
                401,
                [
                    'error'             => OAuth2ResponseFactoryManagerInterface::ERROR_INVALID_CLIENT,
                    'error_description' => 'Client authentication failed.',
                ]
            );
        }

        if (null !== $grantTypeResponse->getClient() && $grantTypeResponse->getClient()->getId()->getValue() !== $client->getId()->getValue()) {
            throw new  OAuth2Exception(
                401,
                [
                    'error'             => OAuth2ResponseFactoryManagerInterface::ERROR_INVALID_CLIENT,
                    'error_description' => 'Client authentication failed.',
                ]
            );
        }

        // - We add the subject as the client public id
        $grantTypeResponse = $grantTypeResponse->withClient($client);

        // - We transmit the JWT to the response for further needs
        $grantTypeResponse = $grantTypeResponse->withMetadata('jwt', $jwt);

        return $grantTypeResponse;
    }

    /**
     * {@inheritdoc}
     */
    public function grant(ServerRequestInterface $request, GrantTypeData $grantTypeResponse): GrantTypeData
    {
        if (false === $grantTypeResponse->getClient()->hasPublicKeySet()) {
            throw new OAuth2Exception(400,
                [
                    'error'             => OAuth2ResponseFactoryManagerInterface::ERROR_INVALID_CLIENT,
                    'error_description' => 'The client is not a client with signature capabilities.',
                ]
            );
        }
        $jwt = $grantTypeResponse->getMetadata('jwt');

        try {
            $this->jwtLoader->verify(
                $jwt,
                $grantTypeResponse->getClient()->getPublicKeySet()
            );
        } catch (\Exception $e) {
            throw new OAuth2Exception(
                400,
                [
                    'error'             => OAuth2ResponseFactoryManagerInterface::ERROR_INVALID_REQUEST,
                    'error_description' => $e->getMessage(),
                ]
            );
        }

        $grantTypeResponse = $grantTypeResponse->withResourceOwner($grantTypeResponse->getClient());
        if ($issueRefreshToken = $this->isRefreshTokenIssuedWithAccessToken()) {
            $grantTypeResponse = $grantTypeResponse->withRefreshToken();
        } else {
            $grantTypeResponse = $grantTypeResponse->withRefreshToken();
            $grantTypeResponse->withRefreshTokenScopes($grantTypeResponse->getScopes());
        }

        //$grantTypeResponse->setUserAccountPublicId(null);
        return $grantTypeResponse;
    }

    /**
     * @return bool
     */
    public function isRefreshTokenIssuedWithAccessToken(): bool
    {
        return $this->issueRefreshToken;
    }

    public function enableRefreshTokenIssuanceWithAccessToken()
    {
        $this->issueRefreshToken = true;
    }

    public function disableRefreshTokenIssuanceWithAccessToken()
    {
        $this->issueRefreshToken = false;
    }
}
