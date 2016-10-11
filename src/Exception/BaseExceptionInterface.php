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
     * Gets the message.
     * This method comes from the \Throwable interface available since PHP 7.0
     *
     * @link http://php.net/manual/en/throwable.getmessage.php
     * @return string
     */
    public function getMessage();

    /**
     * Gets the exception code.
     * This method comes from the \Throwable interface available since PHP 7.0
     *
     * @link http://php.net/manual/en/throwable.getcode.php
     * @return int
     */
    public function getCode();

    /**
     * Gets the file in which the exception occurred.
     * This method comes from the \Throwable interface available since PHP 7.0
     *
     * @link http://php.net/manual/en/throwable.getfile.php
     * @return string Returns the name of the file from which the object was thrown.
     */
    public function getFile();

    /**
     * Gets the line on which the object was instantiated.
     * This method comes from the \Throwable interface available since PHP 7.0
     *
     * @link http://php.net/manual/en/throwable.getline.php
     * @return int Returns the line number where the thrown object was instantiated.
     */
    public function getLine();

    /**
     * Gets the stack trace.
     * This method comes from the \Throwable interface available since PHP 7.0
     *
     * @link http://php.net/manual/en/throwable.gettrace.php
     * @return array
     */
    public function getTrace();

    /**
     * Gets the stack trace as a string.
     * This method comes from the \Throwable interface available since PHP 7.0
     *
     * @link http://php.net/manual/en/throwable.gettraceasstring.php
     * @return string Returns the stack trace as a string.
     */
    public function getTraceAsString();

    /**
     * Returns the previous Throwable.
     * This method comes from the \Throwable interface available since PHP 7.0
     *
     * @link http://php.net/manual/en/throwable.getprevious.php
     * @return \OAuth2\Exception\BaseExceptionInterface|\Exception|null
     */
    public function getPrevious();

    /**
     * Gets a string representation of the thrown object.
     * This method comes from the \Throwable interface available since PHP 7.0
     *
     * @link http://php.net/manual/en/throwable.tostring.php
     * @return string
     */
    public function __toString();

    /**
     * Get the description of the exception.
     *
     * @return string
     */
    public function getDescription();

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
