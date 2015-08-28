<?php

namespace OAuth2\Exception;

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
     * @return \Symfony\Component\HttpFoundation\Response
     */
    public function getHttpResponse();
}
