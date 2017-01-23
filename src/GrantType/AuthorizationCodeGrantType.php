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

namespace OAuth2\GrantType;

use Assert\Assertion;
use OAuth2\Endpoint\Token\GrantTypeData;
use OAuth2\GrantType\PKCEMethod\PKCEMethodManagerInterface;
use OAuth2\Model\AuthCode\AuthCode;
use OAuth2\Model\AuthCode\AuthCodeId;
use OAuth2\Model\AuthCode\AuthCodeRepositoryInterface;
use OAuth2\Model\Client\Client;
use OAuth2\Response\OAuth2Exception;
use OAuth2\Response\OAuth2ResponseFactoryManagerInterface;
use Psr\Http\Message\ServerRequestInterface;
use Psr\Http\Message\UriInterface;
use SimpleBus\Message\Bus\MessageBus;

class AuthorizationCodeGrantType implements GrantTypeInterface
{
    /**
     * @var AuthCodeRepositoryInterface
     */
    private $authCodeRepository;

    /**
     * @var PKCEMethodManagerInterface
     */
    private $pkceMethodManager;

    /**
     * @var MessageBus
     */
    private $commandBus;

    /**
     * AuthorizationCodeGrantType constructor.
     *
     * @param AuthCodeRepositoryInterface $authCodeRepository
     * @param PKCEMethodManagerInterface  $pkceMethodManager
     * @param MessageBus                  $commandBus
     */
    public function __construct(AuthCodeRepositoryInterface $authCodeRepository, PKCEMethodManagerInterface $pkceMethodManager, MessageBus $commandBus)
    {
        $this->authCodeRepository = $authCodeRepository;
        $this->pkceMethodManager = $pkceMethodManager;
        $this->commandBus = $commandBus;
    }

    /**
     * {@inheritdoc}
     */
    public function getAssociatedResponseTypes(): array
    {
        return ['code'];
    }

    /**
     * {@inheritdoc}
     */
    public function getGrantType(): string
    {
        return 'authorization_code';
    }

    /**
     * {@inheritdoc}
     */
    public function checkTokenRequest(ServerRequestInterface $request)
    {
        $parameters = $request->getParsedBody() ?? [];
        $requiredParameters = ['code'];

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
        //Nothing to do
        return $grantTypeResponse;
    }

    /**
     * {@inheritdoc}
     */
    public function grant(ServerRequestInterface $request, GrantTypeData $grantTypeResponse): GrantTypeData
    {
        $parameters = $request->getParsedBody() ?? [];
        $this->checkClient($grantTypeResponse->getClient(), $parameters);
        $authCode = $this->getAuthCode($parameters['code']);

        $this->checkPKCE($authCode, $parameters);
        $this->checkAuthCode($authCode, $grantTypeResponse->getClient());

        $redirect_uri = array_key_exists('redirect_uri', $parameters) ? $parameters['redirect_uri'] : null;

        // Validate the redirect URI.
        $this->checkRedirectUri($authCode, $redirect_uri);
        $grantTypeResponse = $grantTypeResponse->withMetadata('redirect_uri', $redirect_uri);

        $availableScopes = $authCode->getScopes();
        if (!empty($availableScopes)) {
            $requestedScopes = array_key_exists('scope', $parameters) ? $parameters['scope'] : null;
            //$grantTypeResponse->setRequestedScope(RequestBody::getParameter($request, 'scope') ? $this->getScopeManager()->convertToArray(RequestBody::getParameter($request, 'scope')) : $authCode->getScope());

            // Check if requested scopes are within the available scopes

            $grantTypeResponse = $grantTypeResponse->withScopes($availableScopes);
        }
        $grantTypeResponse = $grantTypeResponse->withResourceOwner($authCode->getResourceOwner());
        //$grantTypeResponse = $grantTypeResponse->withUserAccountPublicId($authCode->getUserAccountPublicId());

        // Refresh Token
        if ($authCode->isRefreshTokenIssued()) {
            $grantTypeResponse = $grantTypeResponse->withRefreshToken();
            $grantTypeResponse = $grantTypeResponse->withRefreshTokenScopes($availableScopes);
        } else {
            $grantTypeResponse = $grantTypeResponse->withoutRefreshToken();
        }
        $grantTypeResponse->setMetadata('auth_code', $authCode);

        $authCodeUsedCommand = MarkAuthCodeAsUsedCommand::create();
        $this->commandBus->handle($authCodeUsedCommand);
    }

    /**
     * @param string $code
     *
     * @throws OAuth2Exception
     *
     * @return AuthCode
     */
    private function getAuthCode(string $code)
    {
        $authCode = $this->authCodeRepository->find(AuthCodeId::create($code));

        if (!$authCode instanceof AuthCode) {
            throw new OAuth2Exception(
                400,
                [
                    'error'             => OAuth2ResponseFactoryManagerInterface::ERROR_INVALID_GRANT,
                    'error_description' => 'Code does not exist or is invalid for the client.',
                ]
            );
        }

        return $authCode;
    }

    /**
     * @param Client $client
     * @param array  $parameters
     *
     * @throws OAuth2Exception
     */
    private function checkClient(Client $client, array $parameters)
    {
        if (true === $client->isPublic()) {
            if (!array_key_exists('client_id', $parameters) || $client->getId()->getValue() !== $parameters['client_id']) {
                throw new OAuth2Exception(
                    400,
                    [
                        'error'             => OAuth2ResponseFactoryManagerInterface::ERROR_INVALID_REQUEST,
                        'error_description' => 'The \'client_id\' parameter is required for non-confidential clients.',
                    ]
                );
            }
        }
    }

    /**
     * @param \OAuth2\Model\AuthCode\AuthCode $authCode
     * @param array                           $parameters
     *
     * @throws OAuth2Exception
     */
    private function checkPKCE(AuthCode $authCode, array $parameters)
    {
        $params = $authCode->getQueryParams();
        if (!array_key_exists('code_challenge', $params)) {
            return;
        }

        $code_challenge = $params['code_challenge'];
        $code_challenge_method = array_key_exists('code_challenge_method', $params) ? $params['code_challenge_method'] : 'plain';

        try {
            Assertion::keyExists($parameters, 'code_verifier', 'The parameter \'code_verifier\' is missing.');
            $code_verifier = $parameters['code_verifier'];
            $this->pkceMethodManager->checkPKCEInput($code_challenge_method, $code_challenge, $code_verifier);
        } catch (\InvalidArgumentException $e) {
            throw new OAuth2Exception(
                400,
                [
                    'error'             => OAuth2ResponseFactoryManagerInterface::ERROR_INVALID_REQUEST,
                    'error_description' => $e->getMessage(),
                ]
            );
        }
    }

    /**
     * @param \OAuth2\Model\AuthCode\AuthCode $authCode
     * @param UriInterface                    $redirect_uri
     *
     * @throws OAuth2Exception
     */
    private function checkRedirectUri(AuthCode $authCode, UriInterface $redirect_uri)
    {
        if (true === $authCode->hasMetadata('redirect_uri') && $redirect_uri !== $authCode->getMetadata('redirect_uri')) {
            throw new OAuth2Exception(
                400,
                [
                    'error' => OAuth2ResponseFactoryManagerInterface::ERROR_INVALID_REQUEST,
                    'The redirect URI is missing or does not match.',
                ]
            );
        }
    }

    /**
     * @param \OAuth2\Model\AuthCode\AuthCode $authCode
     * @param Client                          $client
     *
     * @throws OAuth2Exception
     */
    private function checkAuthCode(AuthCode $authCode, Client $client)
    {
        if ($client->getId()->getValue() !== $authCode->getClientId()->getValue()) {
            throw new OAuth2Exception(
                400,
                [
                    'error'             => OAuth2ResponseFactoryManagerInterface::ERROR_INVALID_GRANT,
                    'error_description' => "Code doesn't exist or is invalid for the client.",
                ]
            );
        }

        if ($authCode->hasExpired()) {
            throw new OAuth2Exception(
                400,
                [
                    'error'             => OAuth2ResponseFactoryManagerInterface::ERROR_INVALID_GRANT,
                    'error_description' => 'The authorization code has expired.',
                ]
            );
        }
    }
}
