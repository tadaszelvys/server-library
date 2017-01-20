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

namespace OAuth2\Test\Stub;

use OAuth2\Response\Factory\AuthenticateResponseFactory as Base;
use OAuth2\Response\OAuth2ResponseInterface;
use OAuth2\TokenEndpointAuthMethod\TokenEndpointAuthMethodManagerInterface;
use Psr\Http\Message\ResponseInterface;

class AuthenticateResponseFactory extends Base
{
    /**
     * @var TokenEndpointAuthMethodManagerInterface
     */
    private $tokenEndpointAuthMethodManager;

    /**
     * ClientAuthenticationMiddleware constructor.
     *
     * @param TokenEndpointAuthMethodManagerInterface $tokenEndpointAuthMethodManager
     */
    public function __construct(TokenEndpointAuthMethodManagerInterface $tokenEndpointAuthMethodManager)
    {
        $this->tokenEndpointAuthMethodManager = $tokenEndpointAuthMethodManager;
    }

    /**
     * {@inheritdoc}
     */
    public function createResponse(array $data, ResponseInterface &$response): OAuth2ResponseInterface
    {
        $schemes = [];
        foreach ($this->tokenEndpointAuthMethodManager->getTokenEndpointAuthMethods() as $method) {
            $scheme = $method->getSchemesParameters();
            $schemes = array_merge($schemes, $scheme);
        }

        return parent::createResponse($data, $response);
    }

    /**
     * {@inheritdoc}
     */
    protected function getSchemes(): array
    {
        return ['Bearer realm="My service"', 'MAC'];
    }
}
