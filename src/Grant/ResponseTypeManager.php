<?php

/*
 * The MIT License (MIT)
 *
 * Copyright (c) 2014-2016 Spomky-Labs
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file for details.
 */

namespace OAuth2\Grant;

use Assert\Assertion;

class ResponseTypeManager implements ResponseTypeManagerInterface
{
    /**
     * @var \OAuth2\Grant\ResponseTypeInterface[]
     */
    private $response_types = [];

    /**
     * {@inheritdoc}
     */
    public function addResponseType(ResponseTypeInterface $response_type)
    {
        $this->response_types[$response_type->getResponseType()] = $response_type;
    }

    /**
     * {@inheritdoc}
     */
    public function hasResponseType($name)
    {
        return array_key_exists($name, $this->response_types);
    }

    /**
     * {@inheritdoc}
     */
    public function getResponseTypes($names)
    {
        Assertion::true($this->isResponseTypeSupported($names), sprintf('The response type "%s" is not supported.', $names));
        $response_types = explode(' ', $names);

        $types = [];
        foreach ($response_types as $response_type) {
            $type = $this->response_types[$response_type];
            $types[] = $type;
        }

        return $types;
    }

    /**
     * {@inheritdoc}
     */
    public function getSupportedResponseTypes()
    {
        $types = array_keys($this->response_types);
        if (in_array('id_token', $types)) {
            if (in_array('code', $types)) {
                $types[] = 'code id_token';
            }
            if (in_array('token', $types)) {
                $types[] = 'id_token token';
            }
            if (in_array('code', $types) && in_array('token', $types)) {
                $types[] = 'code id_token token';
            }
        }
        if (in_array('code', $types) && in_array('token', $types)) {
            $types[] = 'code token';
        }

        return $types;
    }

    /**
     * {@inheritdoc}
     */
    public function isResponseTypeSupported($response_type)
    {
        return in_array($response_type, $this->getSupportedResponseTypes());
    }
}
