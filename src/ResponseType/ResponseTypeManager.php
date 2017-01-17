<?php

/*
 * The MIT License (MIT)
 *
 * Copyright (c) 2014-2016 Spomky-Labs
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file for details.
 */

namespace OAuth2\ResponseType;

use Assert\Assertion;

class ResponseTypeManager implements ResponseTypeManagerInterface
{
    /**
     * @var ResponseTypeInterface[]
     */
    private $responseTypes = [];

    /**
     * {@inheritdoc}
     */
    public function addResponseType(ResponseTypeInterface $responseType): ResponseTypeManagerInterface
    {
        $this->responseTypes[$responseType->getResponseType()] = $responseType;

        return $this;
    }

    /**
     * {@inheritdoc}
     */
    public function hasResponseType(string $name): bool
    {
        return array_key_exists($name, $this->responseTypes);
    }

    /**
     * {@inheritdoc}
     */
    public function getResponseTypes(string $names): array
    {
        Assertion::true($this->isResponseTypeSupported($names), sprintf('The response type \'%s\' is not supported.', $names));
        $responseTypes = explode(' ', $names);

        $types = [];
        foreach ($responseTypes as $responseType) {
            $type = $this->responseTypes[$responseType];
            $types[] = $type;
        }

        return $types;
    }

    /**
     * {@inheritdoc}
     */
    public function getSupportedResponseTypes(): array
    {
        $types = array_keys($this->responseTypes);
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
    public function isResponseTypeSupported(string $responseType): bool
    {
        return in_array($responseType, $this->getSupportedResponseTypes());
    }
}
