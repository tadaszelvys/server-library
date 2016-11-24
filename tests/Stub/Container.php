<?php

namespace OAuth2\Test\Stub;

use Psr\Container\ContainerInterface;

final class Container implements ContainerInterface
{
    /**
     * @var array
     */
    private $services = [];

    /**
     * @param $service
     * @return mixed
     */
    public function add($service)
    {
        $class = get_class($service);
        $this->services[$class] = $service;
    }

    /**
     * {@inheritdoc}
     */
    public function get($id)
    {
        if ($this->has($id)) {
            return $this->services[$id];
        }
    }

    /**
     * {@inheritdoc}
     */
    public function has($id)
    {
        return array_key_exists($id, $this->services);
    }
}
