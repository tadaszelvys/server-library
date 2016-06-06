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

use OAuth2\Exception\Extension\ExceptionExtensionInterface;
use OAuth2\Exception\Factory\ExceptionFactoryInterface;

/**
 * An exception manager.
 *
 * @method \OAuth2\Exception\AuthenticateExceptionInterface getAuthenticateException(string $error, string $error_description = null, array $data = [])
 * @method \OAuth2\Exception\BadRequestExceptionInterface getBadRequestException(string $error, string $error_description = null, array $data = [])
 * @method \OAuth2\Exception\NotImplementedExceptionInterface getNotImplementedException(string $error, string $error_description = null, array $data = [])
 * @method \OAuth2\Exception\RedirectExceptionInterface getRedirectException(string $error, string $error_description = null, array $data = [])
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

    //Error messages from OpenID Connect specifications
    const INTERACTION_REQUIRED = 'interaction_required';
    const LOGIN_REQUIRED = 'login_required';
    const ACCOUNT_SELECTION_REQUIRED = 'account_selection_required';
    const CONSENT_REQUIRED = 'consent_required';
    const INVALID_REQUEST_URI = 'invalid_request_uri';
    const INVALID_REQUEST_OBJECT = 'invalid_request_object';
    const REQUEST_NOT_SUPPORTED = 'request_not_supported';
    const REQUEST_URI_NOT_SUPPORTED = 'request_uri_not_supported';
    const REGISTRATION_NOT_SUPPORTED = 'registration_not_supported';

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

    /**
     * @param \OAuth2\Exception\Extension\ExceptionExtensionInterface $extension
     */
    public function addExtension(ExceptionExtensionInterface $extension);

    /**
     * @param \OAuth2\Exception\Factory\ExceptionFactoryInterface $exception_factory
     *
     * @return mixed
     */
    public function addExceptionFactory(ExceptionFactoryInterface $exception_factory);
}
