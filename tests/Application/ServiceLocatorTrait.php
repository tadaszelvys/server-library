<?php

namespace OAuth2\Test\Application;

use OAuth2\Test\Stub\Container;
use OAuth2\Test\Stub\ServiceLocator;

trait ServiceLocatorTrait
{
    abstract public function getContainer(): Container;

    /**
     * @var null|ServiceLocator
     */
    private $serviceLocator = null;

    /**
     * @return ServiceLocator
     */
    public function getServiceLocator(): ServiceLocator
    {
        if (null === $this->serviceLocator) {
            $this->serviceLocator = new ServiceLocator(
                $this->getContainer()
            );
        }

        return $this->serviceLocator;
    }
}
