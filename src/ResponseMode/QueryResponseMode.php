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

use OAuth2\Grant\ResponseTypeInterface;
use OAuth2\Util\Uri;
use Psr\Http\Message\ResponseInterface;
use Zend\Diactoros\Response;

class QueryResponseMode implements ResponseModeInterface
{
    /**
     * {@inheritdoc}
     */
    public function getName(): string
    {
        return ResponseTypeInterface::RESPONSE_TYPE_MODE_QUERY;
    }

    /**
     * {@inheritdoc}
     */
    public function prepareResponse(string $redirect_uri, array $data): ResponseInterface
    {
        $params = empty($data) ? [] : [$this->getName() => $data];
        if (!array_key_exists('fragment', $params)) {
            $params['fragment'] = [];
        }

        $response = new Response('php://memory', 302);
        $response = $response->withHeader('Location', Uri::buildURI($redirect_uri, $params));

        return $response;
    }
}
