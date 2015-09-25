<?php

namespace OAuth2\Behaviour;

use OAuth2\Endpoint\ResponseModeInterface;

trait HasResponseModeSupport
{
    /**
     * @var \OAuth2\Endpoint\ResponseModeInterface[]
     */
    protected $response_modes;

    /**
     * @param string $name
     *
     * @return null|\OAuth2\Endpoint\ResponseModeInterface
     */
    public function getResponseMode($name)
    {
        return array_key_exists($name, $this->response_modes)?$this->response_modes[$name]:null;
    }

    /**
     * @return \OAuth2\Endpoint\ResponseModeInterface[]
     */
    public function getResponseModes()
    {
        return $this->response_modes;
    }

    /**
     * @param \OAuth2\Endpoint\ResponseModeInterface $response_mode
     *
     * @return self
     */
    public function addResponseMode(ResponseModeInterface $response_mode)
    {
        $this->response_modes[$response_mode->getName()] = $response_mode;

        return $this;
    }
}
