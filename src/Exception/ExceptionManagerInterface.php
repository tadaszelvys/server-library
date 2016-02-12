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

/**
 * An exception manager.
 *
 * @method getAuthenticateException(string $error, null $error_description, array $data = [])
 * @method getBadRequestException(string $error, null $error_description, array $data = [])
 * @method getNotImplementedException(string $error, null $error_description, array $data = [])
 * @method getRedirectException(string $error, null $error_description, array $data = [])
 * @method getInternalServerErrorException(string $error, null $error_description, array $data = [])
 */
interface ExceptionManagerInterface
{
    //Types of exception
    const AUTHENTICATE = 'Authenticate';
    const BAD_REQUEST = 'BadRequest';
    const NOT_IMPLEMENTED = 'NotImplemented';
    const REDIRECT = 'Redirect';
    const INTERNAL_SERVER_ERROR = 'InternalServerError';

    //Error messages
    const INVALID_REQUEST = 'invalid_request';
    const INVALID_CLIENT = 'invalid_client';
    const INVALID_GRANT = 'invalid_grant';
    const INVALID_SCOPE = 'invalid_scope';
    const INVALID_TOKEN = 'invalid_token';
    const UNAUTHORIZED_CLIENT = 'unauthorized_client';
    const UNSUPPORTED_GRANT_TYPE = 'unsupported_grant_type';
    const ACCESS_DENIED = 'access_denied';
    const UNSUPPORTED_RESPONSE_TYPE = 'unsupported_response_type';
    const SERVER_ERROR = 'server_error';
    const TEMPORARILY_UNAVAILABLE = 'temporarily_unavailable';

    /**
     * This function will try to get the URI to a human readable page according to the type, error and description of the exception.
     *
     * @param string      $type              The type of the exception
     * @param string      $error             Short name of the error
     * @param string|null $error_description Description of the error (optional)
     * @param array       $data              Additional data sent to the exception (optional)
     *
     * @return string|null
     */
    public function getUri($type, $error, $error_description = null, array $data = []);

    /**
     * This function will try to get the URI according to the type, error and description of the exception.
     *
     * @param string      $type              The type of the exception
     * @param string      $error             Short name of the error
     * @param string|null $error_description Description of the error (optional)
     * @param array       $data              Additional data sent to the exception (optional)
     *
     * @return \OAuth2\Exception\BaseExceptionInterface
     */
    public function getException($type, $error, $error_description = null, array $data = []);
}
