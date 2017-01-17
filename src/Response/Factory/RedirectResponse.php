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

use OAuth2\Response\OAuth2Response;
use OAuth2\ResponseMode\ResponseModeInterface;
use Psr\Http\Message\ResponseInterface;

class RedirectResponse extends OAuth2Response
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
     * RedirectResponse constructor.

     * @param string                                     $redirect_uri
     * @param \OAuth2\ResponseMode\ResponseModeInterface $response_mode
     * @param string|array                               $data
     * @param \Psr\Http\Message\ResponseInterface        $response
     */
    public function __construct($redirect_uri, ResponseModeInterface $response_mode, $data, ResponseInterface $response)
    {
        parent::__construct(302, $data, $response);

        $this->response_mode = $response_mode;
        $this->redirect_uri = $redirect_uri;
    }

    /**
     * {@inheritdoc}
     */
    public function getResponse()
    {
        $this->response = $this->response_mode->prepareResponse($this->redirect_uri, $this->getData());

        foreach ($this->getHeaders() as $header => $value) {
            $this->response = $this->response->withHeader($header, $value);
        }

        return $this->response;
    }

    /**
     * {@inheritdoc}
     */
    public function getBody()
    {
    }

    /**
     * {@inheritdoc}
     */
    public function getHeaders()
    {
        $headers = parent::getHeaders();
        $headers['Content-Security-Policy'] = 'referrer origin;'; // The header is used to mitigate closing redirectors

        return $headers;
    }
}
