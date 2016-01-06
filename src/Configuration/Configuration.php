<?php

/*
 * The MIT License (MIT)
 *
 * Copyright (c) 2014-2016 Spomky-Labs
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
    private $config = [];

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
    public function has($name)
    {
        return array_key_exists($name, $this->config);
    }

    /**
     * {@inheritdoc}
     */
    public function get($name, $default = null)
    {
        if ($this->has($name)) {
            return $this->config[$name];
        }

        return $default;
    }

    /**
     * {@inheritdoc}
     */
    public function set($name, $value)
    {
        $this->config[$name] = $value;
    }

    /**
     * {@inheritdoc}
     */
    public function delete($name)
    {
        if (isset($this->config[$name])) {
            unset($this->config[$name]);
        }
    }
}
