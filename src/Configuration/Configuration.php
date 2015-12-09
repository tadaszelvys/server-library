<?php

/*
 * The MIT License (MIT)
 *
 * Copyright (c) 2014-2015 Spomky-Labs
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file for details.
 */

namespace OAuth2\Configuration;

final class Configuration implements ConfigurationInterface
{
    /**
     * @var array
     */
    protected $config = [];

    /**
     * @param array $values
     */
    public function __construct(array $values = [])
    {
        $this->config = $values;
    }

    /**
     * {@inheritdoc}
     */
    public function get($name, $default = null)
    {
        return isset($this->config[$name]) ? $this->config[$name] : $default;
    }

    /**
     * @param string $name
     * @param mixed  $value
     *
     * @return self
     */
    public function set($name, $value)
    {
        $this->config[$name] = $value;

        return $this;
    }

    /**
     * @param string $name
     *
     * @return self
     */
    public function delete($name)
    {
        if (isset($this->config[$name])) {
            unset($this->config[$name]);
        }

        return $this;
    }
}
