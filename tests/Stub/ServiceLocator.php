<?php

namespace OAuth2\Test\Stub;

use Psr\Container\ContainerInterface;

final class ServiceLocator
{
    /**
     * @var ContainerInterface
     */
    private $container;

    /**
     * ServiceLocator constructor.
     * @param ContainerInterface $container
     */
    public function __construct(ContainerInterface $container)
    {
        $this->container = $container;
    }

    /**
     * @param string $service
     * @return null|callable
     */
    public function __invoke(string $service)
    {
        if ($this->container->has($service)) {
            return $this->container->get($service);
        }
    }
}
