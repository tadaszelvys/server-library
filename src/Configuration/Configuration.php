<?php

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
     */
    public function set($name, $value)
    {
        $this->config[$name] = $value;
    }

    /**
     * @param string $name
     */
    public function delete($name)
    {
        if (isset($this->config[$name])) {
            unset($this->config[$name]);
        }
    }
}
