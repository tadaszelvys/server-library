<?php

/*
 * The MIT License (MIT)
 *
 * Copyright (c) 2014-2016 Spomky-Labs
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file for details.
 */

namespace OAuth2\Endpoint;

use OAuth2\Util\Uri;
use Psr\Http\Message\ResponseInterface;

final class FragmentResponseMode implements ResponseModeInterface
{
    /**
     * {@inheritdoc}
     */
    public function getName()
    {
        return 'fragment';
    }

    /**
     * {@inheritdoc}
     */
    public function prepareResponse($redirect_uri, array $data, ResponseInterface &$response)
    {
        $params = empty($data) ? [] : [$this->getName() => $data];

        $response = $response->withStatus(302)
            ->withHeader('Location', Uri::buildUri($redirect_uri, $params));
    }
}
