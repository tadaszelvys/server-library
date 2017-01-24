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

namespace OAuth2\ResponseType;

interface ResponseTypeManagerInterface
{
    /**
     * @param ResponseTypeInterface $responseType
     *
     * @return ResponseTypeManagerInterface
     */
    public function add(ResponseTypeInterface $responseType): self;

    /**
     * @param string $name
     *
     * @return bool
     */
    public function has(string $name): bool;

    /**
     * @param string $names
     *
     * @throws \InvalidArgumentException
     *
     * @return ResponseTypeInterface[]
     */
    public function find(string $names): array;

    /**
     * @return string[]
     */
    public function all(): array;

    /**
     * @param string $responseType
     *
     * @return bool
     */
    public function isSupported(string $responseType): bool;
}
