<?php declare(strict_types=1);

/*
 * The MIT License (MIT)
 *
 * Copyright (c) 2014-2016 Spomky-Labs
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file for details.
 */

namespace OAuth2\ResponseMode;

interface ResponseModeManagerInterface
{
    /**
     * @param ResponseModeInterface $responseMode
     */
    public function add(ResponseModeInterface $responseMode);

    /**
     * @param string $name
     *
     * @return bool
     */
    public function has(string $name): bool;

    /**
     * @param string $name
     *
     * @throws \InvalidArgumentException
     *
     * @return ResponseModeInterface
     */
    public function get(string $name): ResponseModeInterface;

    /**
     * @return string[]
     */
    public function list(): array;
}
