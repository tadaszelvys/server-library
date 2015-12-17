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

interface ConfigurationInterface
{
    /**
     * @param string $name Name of the option
     *
     * @return bool Returns true if the configuration has an option value named `$name`
     */
    public function has($name);

    /**
     * @param string $name    Name of the option
     * @param mixed  $default Default value if the option is not set
     *
     * @return mixed The value of the the option or $default if not found
     */
    public function get($name, $default = null);

    /**
     * @param string $name Name of the option
     * @param mixed $value Value of the option
     *
     * @return mixed
     */
    public function set($name, $value);

    /**
     * @param string $name Name of the option
     *
     * @return mixed
     */
    public function delete($name);
}
