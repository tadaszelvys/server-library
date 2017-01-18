<?php

declare(strict_types=1);

/*
 * The MIT License (MIT)
 *
 * Copyright (c) 2014-2017 Spomky-Labs
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file for details.
 */

namespace OAuth2\ResponseMode;

use Assert\Assertion;

class ResponseModeManager implements ResponseModeManagerInterface
{
    /**
     * @var \OAuth2\ResponseMode\ResponseModeInterface[]
     */
    private $responseModes = [];

    /**
     * {@inheritdoc}
     */
    public function add(ResponseModeInterface $responseMode)
    {
        $this->responseModes[$responseMode->getName()] = $responseMode;
    }

    /**
     * {@inheritdoc}
     */
    public function has(string $name): bool
    {
        return array_key_exists($name, $this->responseModes);
    }

    /**
     * {@inheritdoc}
     */
    public function get(string $name): ResponseModeInterface
    {
        Assertion::true($this->hasResponseMode($name), sprintf('The response mode with name \'%s\' is not supported.', $name));

        return $this->responseModes[$name];
    }

    /**
     * {@inheritdoc}
     */
    public function list(): array
    {
        return array_keys($this->responseModes);
    }
}
