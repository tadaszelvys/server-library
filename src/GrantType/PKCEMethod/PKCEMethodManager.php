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

class PKCEMethodManager implements PKCEMethodManagerInterface
{
    /**
     * @var PKCEMethodInterface[]
     */
    private $pkceMethods = [];

    /**
     * {@inheritdoc}
     */
    public function addPKCEMethod(PKCEMethodInterface $method): PKCEMethodManagerInterface
    {
        $this->pkceMethods[$method->getMethodName()] = $method;

        return $this;
    }

    /**
     * {@inheritdoc}
     */
    public function hasPKCEMethod(string $method): bool
    {
        return array_key_exists($method, $this->pkceMethods);
    }

    /**
     * {@inheritdoc}
     */
    public function getPKCEMethod(string $method): PKCEMethodInterface
    {
        return $this->pkceMethods[$method];
    }

    /**
     * {@inheritdoc}
     */
    public function getPKCEMethods(): array
    {
        return array_values($this->pkceMethods);
    }

    /**
     * {@inheritdoc}
     */
    public function getPKCEMethodNames(): array
    {
        return array_keys($this->pkceMethods);
    }
}
