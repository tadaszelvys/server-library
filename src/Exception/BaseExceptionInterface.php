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

use Psr\Http\Message\ResponseInterface;

/**
 * OAuth2 Exception that requires termination of process.
 * This exception is the base of all other exceptions. It might not be used directly.
 */
interface BaseExceptionInterface
{
    /**
     * Get the description of the exception.
     *
     * @return string
     */
    public function getDescription();

    /**
     * Get the uri to a human-readable web page with more information about the error.
     *
     * @return string
     */
    public function getUri();

    /**
     * Get HTTP code (30x, 40x, 50x…).
     *
     * @return int
     */
    public function getHttpCode();

    /**
     * Get HTTP Error Response headers.
     *
     * @return array
     *
     * @see http://tools.ietf.org/html/rfc6749#section-5.2
     */
    public function getResponseHeaders();

    /**
     * Get response body as JSON string.
     *
     * @return string
     */
    public function getResponseBody();

    /**
     * Get the exception as a Response object.
     *
     * @param \Psr\Http\Message\ResponseInterface $response
     */
    public function getHttpResponse(ResponseInterface &$response);

    /**
     * @return array
     */
    public function getResponseData();
}
