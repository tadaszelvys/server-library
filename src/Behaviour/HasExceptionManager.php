<?php

namespace OAuth2\Behaviour;

use OAuth2\Exception\ExceptionManagerInterface;

trait HasExceptionManager
{
    /**
     * @var\OAuth2\Exception\ExceptionManagerInterface
     */
    private $exception_manager;

    /**
     * @return \OAuth2\Exception\ExceptionManagerInterface
     */
    protected function getExceptionManager()
    {
        return $this->exception_manager;
    }

    /**
     * @param \OAuth2\Exception\ExceptionManagerInterface $exception_manager
     */
    private function setExceptionManager(ExceptionManagerInterface $exception_manager)
    {
        $this->exception_manager = $exception_manager;
    }
}
