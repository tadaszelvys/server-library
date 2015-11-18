<?php

namespace OAuth2\Configuration;

interface ConfigurationInterface
{
    /**
     * @param string $name    Name of the option
     * @param mixed  $default Default value if the option is not set
     *
     * @return mixed The value of the the option or $default if not found
     */
    public function get($name, $default = null);
}
