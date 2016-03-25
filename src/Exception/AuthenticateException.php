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

final class AuthenticateException extends BaseException implements AuthenticateExceptionInterface
{
    private $header = [];

    /**
     * @param string $error             Short name of the error
     * @param string $error_description Description of the error
     * @param array  $error_data        Data to add to the error
     * @param array  $data              Additional data sent to the exception
     */
    public function __construct($error, $error_description, array $error_data, array $data)
    {
        parent::__construct(401, $error, $error_description, $error_data);

        Assertion::keyExists($data, 'schemes', 'schemes_not_defined');

        $this->header = ['WWW-Authenticate' => $data['schemes']];
    }

    /**
     * {@inheritdoc}
     */
    public function getResponseHeaders()
    {
        return array_merge(parent::getResponseHeaders(), $this->header);
    }

    /**
     * {@inheritdoc}
     */
    public function getResponseBody()
    {
    }
}
