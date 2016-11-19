<?php

/*
 * The MIT License (MIT)
 *
 * Copyright (c) 2014-2016 Spomky-Labs
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file for details.
 */

namespace OAuth2\Exception;

use Assert\Assertion;
use OAuth2\ResponseMode\ResponseModeInterface;
use Psr\Http\Message\ResponseInterface;

class RedirectException extends BaseException implements RedirectExceptionInterface
{
    /**
     * @var string
     */
    private $redirect_uri;

    /**
     * @var \OAuth2\ResponseMode\ResponseModeInterface
     */
    private $response_mode;

    /**
     * @param string $error             Short name of the error
     * @param string $error_description Description of the error
     * @param array  $error_data        Data to add to the error
     * @param array  $data              Additional data sent to the exception
     */
    public function __construct($error, $error_description, array $error_data, array $data)
    {
        parent::__construct(302, $error, $error_description, $error_data);

        Assertion::keyExists($data, 'redirect_uri', 'redirect_uri_not_defined');
        Assertion::keyExists($data, 'response_mode', 'invalid_response_mode');
        Assertion::isInstanceOf($data['response_mode'], ResponseModeInterface::class, 'invalid_response_mode');
        $this->response_mode = $data['response_mode'];
        $this->redirect_uri = $data['redirect_uri'];

        if (array_key_exists('state', $data) && null !== $data['state']) {
            $this->errorData['state'] = $data['state'];
        }
    }

    /**
     * {@inheritdoc}
     */
    public function getHttpResponse(ResponseInterface &$response)
    {
        $this->response_mode->prepareResponse(
            $this->redirect_uri,
            $this->getResponseData(),
            $response
        );

        foreach ($this->getResponseHeaders() as $name => $header) {
            $response = $response->withAddedHeader($name, $header);
        }
    }

    /**
     * {@inheritdoc}
     */
    public function getResponseBody()
    {
    }

    /**
     * {@inheritdoc}
     */
    public function getResponseHeaders()
    {
        return [
            'Content-Security-Policy' => 'referrer origin;', // The header is used to mitigate closing redirectors
        ];
    }
}
