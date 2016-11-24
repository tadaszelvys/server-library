<?php

namespace OAuth2\Test\Application;

use Http\Factory\Diactoros\StreamFactory;
use Interop\Http\Factory\StreamFactoryInterface;

trait StreamFactoryTrait
{
    /**
     * @var null|StreamFactoryInterface
     */
    private $streamFactory = null;

    /**
     * @return StreamFactoryInterface
     */
    public function getStreamFactory(): StreamFactoryInterface
    {
        if (null === $this->streamFactory) {
            $this->streamFactory = new StreamFactory();
        }

        return $this->streamFactory;
    }
}
