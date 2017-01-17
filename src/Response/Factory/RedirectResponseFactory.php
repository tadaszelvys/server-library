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

namespace OAuth2\Response\Factory;

use Assert\Assertion;
use OAuth2\ResponseMode\ResponseModeInterface;
use Psr\Http\Message\ResponseInterface;

class RedirectResponseFactory implements ResponseFactoryInterface
{
    /**
     * {@inheritdoc}
     */
    public function getSupportedCode()
    {
        return 302;
    }

    /**
     * {@inheritdoc}
     */
    public function createResponse($data, ResponseInterface &$response)
    {
        Assertion::isArray($data, 'bad_data_set');
        Assertion::keyExists($data, 'redirect_uri', 'redirect_uri_not_defined');
        Assertion::keyExists($data, 'response_mode', 'invalid_response_mode');
        Assertion::isInstanceOf($data['response_mode'], ResponseModeInterface::class, 'invalid_response_mode');

        $redirect_uri = $data['redirect_uri'];
        $response_mode = $data['response_mode'];

        unset($data['redirect_uri']);
        unset($data['response_mode']);

        return new RedirectResponse($redirect_uri, $response_mode, $data, $response);
    }
}
