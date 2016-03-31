<?php

/*
 * The MIT License (MIT)
 *
 * Copyright (c) 2014-2016 Spomky-Labs
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file for details.
 */

namespace OAuth2\Exception\Extension;

interface ExceptionExtensionInterface
{
    /**
     * @param string      $type              The type of the exception
     * @param string      $error             Short name of the error
     * @param string|null $error_description Description of the error
     * @param array       $data              Additional data sent to the exception
     *
     * @return array
     */
    public function getData($type, $error, $error_description, array $data);
}
