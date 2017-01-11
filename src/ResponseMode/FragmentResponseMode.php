<?php

/*
 * The MIT License (MIT)
 *
 * Copyright (c) 2014-2016 Spomky-Labs
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file for details.
 */

namespace OAuth2\ResponseMode;

use Interop\Http\Factory\ResponseFactoryInterface;
use OAuth2\Grant\ResponseTypeInterface;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\UriInterface;

class FragmentResponseMode implements ResponseModeInterface
{
    /**
     * @var ResponseFactoryInterface
     */
    private $responseFactory;

    /**
     * FragmentResponseMode constructor.
     * @param ResponseFactoryInterface $responseFactory
     */
    public function __construct(ResponseFactoryInterface $responseFactory)
    {
        $this->responseFactory = $responseFactory;
    }

    /**
     * {@inheritdoc}
     */
    public function name(): string
    {
        return ResponseTypeInterface::RESPONSE_TYPE_MODE_FRAGMENT;
    }

    /**
     * {@inheritdoc}
     */
    public function buildResponse(UriInterface $redirectUri, array $data): ResponseInterface
    {
        parse_str($redirectUri->getFragment(), $fragmentParams);
        $fragmentParams += $data;
        $redirectUri = $redirectUri->withFragment(http_build_query($fragmentParams));

        $response = $this->responseFactory->createResponse(302);
        $response = $response->withHeader('Location', $redirectUri->__toString());

        return $response;
    }
}
