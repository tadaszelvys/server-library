<?php

namespace OAuth2\Test\Application;

use Http\Factory\Diactoros\ResponseFactory;
use Interop\Http\Factory\ResponseFactoryInterface;

trait ResponseFactoryTrait
{
    /**
     * @var null|ResponseFactoryInterface
     */
    private $responseFactory = null;

    /**
     * @return ResponseFactoryInterface
     */
    public function getResponseFactory(): ResponseFactoryInterface
    {
        if (null === $this->responseFactory) {
            $this->responseFactory = new ResponseFactory();
        }

        return $this->responseFactory;
    }
}
