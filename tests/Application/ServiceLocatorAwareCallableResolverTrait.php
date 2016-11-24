<?php

namespace OAuth2\Test\Application;

use OAuth2\Test\Stub\ServiceLocator;
use SimpleBus\Message\CallableResolver\ServiceLocatorAwareCallableResolver;

trait ServiceLocatorAwareCallableResolverTrait
{
    abstract public function getServiceLocator(): ServiceLocator;

    /**
     * @var null|ServiceLocatorAwareCallableResolver
     */
    private $serviceLocatorAwareCallableResolver = null;

    /**
     * @return ServiceLocatorAwareCallableResolver
     */
    public function getServiceLocatorAwareCallableResolver(): ServiceLocatorAwareCallableResolver
    {
        if (null === $this->serviceLocatorAwareCallableResolver) {
            $this->serviceLocatorAwareCallableResolver = new ServiceLocatorAwareCallableResolver(
                $this->getServiceLocator()
            );
        }

        return $this->serviceLocatorAwareCallableResolver;
    }
}
