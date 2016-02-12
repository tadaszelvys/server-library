<?php

/*
 * The MIT License (MIT)
 *
 * Copyright (c) 2014-2016 Spomky-Labs
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file for details.
 */

namespace OAuth2\Test\Stub;

use Assert\Assertion;

class Configuration
{
    /**
     * @var array
     */
    private $values = [];

    /**
     * @param string $key
     *
     * @return bool
     */
    public function has($key)
    {
        Assertion::string($key);
        return array_key_exists($key, $this->values);
    }

    /**
     * @param string $key
     *
     * @return mixed
     */
    public function get($key)
    {
        if (true === $this->has($key)) {
            return $this->values[$key];
        }

        throw new \InvalidArgumentException(sprintf('Configuration value with key "%s" does not exist.', $key));
    }

    /**
     * @param string $key
     * @param mixed  $value
     */
    public function set($key, $value)
    {
        Assertion::string($key);
        $this->values[$key] = $value;
    }

    /**
     * @param $key
     */
    public function remove($key)
    {
        if (true === $this->has($key)) {
            unset($this->values[$key]);
        }
    }
}
