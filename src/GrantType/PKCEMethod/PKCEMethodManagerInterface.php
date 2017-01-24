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

namespace OAuth2\GrantType\PKCEMethod;

interface PKCEMethodManagerInterface
{
    /**
     * @param PKCEMethodInterface $method
     *
     * @return self
     */
    public function addPKCEMethod(PKCEMethodInterface $method): PKCEMethodManagerInterface;

    /**
     * @param string $methodName
     *
     * @return bool
     */
    public function hasPKCEMethod(string $methodName): bool;

    /**
     * @param string $methodName
     *
     * @throws \InvalidArgumentException
     *
     * @return PKCEMethodInterface
     */
    public function getPKCEMethod(string $methodName): PKCEMethodInterface;

    /**
     * @return PKCEMethodInterface[]
     */
    public function getPKCEMethods(): array;

    /**
     * @return string[]
     */
    public function getPKCEMethodNames(): array;
}
