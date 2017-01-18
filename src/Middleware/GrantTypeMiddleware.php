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

namespace OAuth2\Middleware;

use Assert\Assertion;
use Interop\Http\ServerMiddleware\DelegateInterface;
use Interop\Http\ServerMiddleware\MiddlewareInterface;
use OAuth2\GrantType\GrantTypeManagerInterface;
use OAuth2\Response\OAuth2Exception;
use OAuth2\Response\OAuth2ResponseFactoryManagerInterface;
use Psr\Http\Message\ServerRequestInterface;

final class GrantTypeMiddleware implements MiddlewareInterface
{
    /**
     * @var GrantTypeManagerInterface
     */
    private $grantTypeManager;

    /**
     * ClientAuthenticationMiddleware constructor.
     *
     * @param GrantTypeManagerInterface $grantTypeManager
     */
    public function __construct(GrantTypeManagerInterface $grantTypeManager)
    {
        $this->grantTypeManager = $grantTypeManager;
    }

    /**
     * {@inheritdoc}
     */
    public function process(ServerRequestInterface $request, DelegateInterface $delegate)
    {
        try {
            $requestParameters = $request->getParsedBody() ?? [];
            Assertion::keyExists($requestParameters, 'grant_type', 'The \'grant_type\' parameter is missing.');
            $grant_type = $requestParameters['grant_type'];
            Assertion::true($this->grantTypeManager->hasGrantType($grant_type), sprintf('The grant type \'%s\' is not supported by this server.', $grant_type));
            $type = $this->grantTypeManager->getGrantType($grant_type);
            $request = $request->withAttribute('grant_type', $type);

            return $delegate->process($request);
        } catch (\InvalidArgumentException $e) {
            throw new OAuth2Exception(400,
                [
                    'error'             => OAuth2ResponseFactoryManagerInterface::ERROR_INVALID_REQUEST,
                    'error_description' => $e->getMessage(),
                ]
            );
        }
    }
}
