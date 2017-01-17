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

interface ResponseTypeManagerInterface
{
    /**
     * @param ResponseTypeInterface $responseType
     * @return ResponseTypeManagerInterface
     */
    public function addResponseType(ResponseTypeInterface $responseType): self;

    /**
     * @param string $name
     *
     * @return bool
     */
    public function hasResponseType(string $name): bool;

    /**
     * @param string $names
     *
     * @throws \InvalidArgumentException
     *
     * @return ResponseTypeInterface[]
     */
    public function getResponseTypes(string $names): array;

    /**
     * @return string[]
     */
    public function getSupportedResponseTypes(): array;

    /**
     * @param string $responseType
     *
     * @return bool
     */
    public function isResponseTypeSupported(string $responseType): bool;
}
