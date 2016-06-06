<?php

/*
 * The MIT License (MIT)
 *
 * Copyright (c) 2014-2016 Spomky-Labs
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file for details.
 */

namespace OAuth2\Exception\Factory;

interface ExceptionFactoryInterface
{
    /**
     * @return string
     */
    public function getType();

    /**
     * @param string $error             Short name of the error
     * @param string $error_description Description of the error
     * @param array  $error_data        Data to add to the error
     * @param array  $data              Additional data sent to the exception
     *
     * @return \OAuth2\Exception\BaseExceptionInterface
     */
    public function createException($error, $error_description, array $error_data, array $data);
}
