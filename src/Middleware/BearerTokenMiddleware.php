<?php

declare(strict_types=1);

/*
 * The MIT License (MIT)
 *
 * Copyright (c) 2014-2016 Spomky-Labs
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file for details.
 */

namespace OAuth2\Middleware;

use Interop\Http\ServerMiddleware\DelegateInterface;
use Interop\Http\ServerMiddleware\MiddlewareInterface;
use OAuth2\Model\AccessToken\AccessTokenRepositoryInterface;
use OAuth2\Response\OAuth2Exception;
use OAuth2\Response\OAuth2ResponseFactoryManagerInterface;
use OAuth2\TokenType\BearerToken;
use Psr\Http\Message\ServerRequestInterface;

class BearerTokenMiddleware implements MiddlewareInterface
{
    /**
     * @var BearerToken
     */
    private $bearerToken;

    /**
     * @var AccessTokenRepositoryInterface
     */
    private $accessTokenRepository;

    /**
     * BearerTokenMiddleware constructor.
     *
     * @param BearerToken                    $bearerToken
     * @param AccessTokenRepositoryInterface $accessTokenRepository
     */
    public function __construct(BearerToken $bearerToken, AccessTokenRepositoryInterface $accessTokenRepository)
    {
        $this->bearerToken = $bearerToken;
        $this->accessTokenRepository = $accessTokenRepository;
    }

    /**
     * {@inheritdoc}
     */
    public function process(ServerRequestInterface $request, DelegateInterface $delegate)
    {
        $additional_credential_values = [];
        $token = $this->bearerToken->findToken($request, $additional_credential_values);
        if (null !== $token) {
            $accessToken = $this->accessTokenRepository->find($token);
            if (null === $accessToken || false === $this->bearerToken->isTokenRequestValid($accessToken, $request, $additional_credential_values)) {
                throw new OAuth2Exception(400, [OAuth2ResponseFactoryManagerInterface::ERROR_INVALID_TOKEN, 'Invalid access token.']);
            }
            $request = $request->withAttribute('access_token', $accessToken);
        }

        return $delegate->process($request);
    }
}
