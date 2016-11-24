<?php

namespace OAuth2\Test\Application;

use Http\Factory\Diactoros\ServerRequestFactory;
use Interop\Http\Factory\ServerRequestFactoryInterface;

trait ServerRequestFactoryTrait
{
    /**
     * @var null|ServerRequestFactoryInterface
     */
    private $serverRequestFactory = null;

    /**
     * @return ServerRequestFactoryInterface
     */
    public function getServerRequestFactory(): ServerRequestFactoryInterface
    {
        if (null === $this->serverRequestFactory) {
            $this->serverRequestFactory = new ServerRequestFactory();
        }

        return $this->serverRequestFactory;
    }
}
