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

class QueryResponseMode implements ResponseModeInterface
{
    /**
     * {@inheritdoc}
     */
    public function getName()
    {
        return ResponseTypeInterface::RESPONSE_TYPE_MODE_QUERY;
    }

    /**
     * {@inheritdoc}
     */
    public function prepareResponse($redirect_uri, array $data, ResponseInterface &$response)
    {
        $params = empty($data) ? [] : [$this->getName() => $data];
        if (!array_key_exists('fragment', $params)) {
            $params['fragment'] = [];
        }

        $response = $response->withStatus(302)
            ->withHeader('Location', Uri::buildURI($redirect_uri, $params));
    }
}
