<?php

use Behat\Behat\Context\Context;
use Http\Factory\Diactoros\ServerRequestFactory;
use Http\Factory\Diactoros\StreamFactory;
use OAuth2\Test\Application\Application;

class BaseContext implements Context
{
    /**
     * @var Application
     */
    private $application;

    /**
     * @var StreamFactory
     */
    private $streamFactory;

    /**
     * @var ServerRequestFactory
     */
    private $serverRequestFactory;

    /**
     * Initializes context.
     *
     * Every scenario gets its own context instance.
     * You can also pass arbitrary arguments to the
     * context constructor through behat.yml.
     */
    public function __construct()
    {
        $this->application = new Application();
        $this->streamFactory = new StreamFactory();
        $this->serverRequestFactory = new ServerRequestFactory();
    }

    /**
     * @return Application
     */
    protected function getApplication(): Application
    {
        return $this->application;
    }

    /**
     * @return StreamFactory
     */
    protected function getStreamFactory(): StreamFactory
    {
        return $this->streamFactory;
    }

    /**
     * @return ServerRequestFactory
     */
    protected function getServerRequestFactory(): ServerRequestFactory
    {
        return $this->serverRequestFactory;
    }
}
