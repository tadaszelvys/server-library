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

namespace OAuth2\ResponseMode;

use Interop\Http\Factory\ResponseFactoryInterface;
use OAuth2\Grant\ResponseTypeInterface;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\UriInterface;

class QueryResponseMode implements ResponseModeInterface
{
    /**
     * @var ResponseFactoryInterface
     */
    private $responseFactory;

    /**
     * QueryResponseMode constructor.
     *
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
        return ResponseTypeInterface::RESPONSE_TYPE_MODE_QUERY;
    }

    /**
     * {@inheritdoc}
     */
    public function buildResponse(UriInterface $redirectUri, array $data): ResponseInterface
    {
        $redirectUri = $redirectUri->withFragment('_=_');
        parse_str($redirectUri->getQuery(), $queryParams);
        $queryParams += $data;
        $redirectUri = $redirectUri->withQuery(http_build_query($queryParams));

        $response = $this->responseFactory->createResponse(302);
        $response = $response->withHeader('Location', $redirectUri->__toString());

        return $response;
    }
}
