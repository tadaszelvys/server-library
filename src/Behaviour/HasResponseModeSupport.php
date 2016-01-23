<?php

/*
 * The MIT License (MIT)
 *
 * Copyright (c) 2014-2016 Spomky-Labs
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file for details.
 */

namespace OAuth2\Behaviour;

use OAuth2\Endpoint\Authorization;
use OAuth2\Endpoint\ResponseModeInterface;
use OAuth2\Exception\ExceptionManagerInterface;
use OAuth2\Grant\ResponseTypeSupportInterface;

trait HasResponseModeSupport
{
    /**
     * @return \OAuth2\Exception\ExceptionManagerInterface
     */
    abstract public function getExceptionManager();

    /**
     * @return \OAuth2\Configuration\ConfigurationInterface
     */
    abstract public function getConfiguration();

    /**
     * @var \OAuth2\Endpoint\ResponseModeInterface[]
     */
    private $response_modes = [];

    /**
     * @param \OAuth2\Grant\ResponseTypeSupportInterface $type
     * @param \OAuth2\Endpoint\Authorization             $authorization
     *
     * @throws \OAuth2\Exception\BaseExceptionInterface
     *
     * @return \OAuth2\Endpoint\ResponseModeInterface
     */
    public function getResponseMode(ResponseTypeSupportInterface $type, Authorization $authorization)
    {
        if ($authorization->has('response_mode')) {
            if ($this->getConfiguration()->get('allow_response_mode_parameter_in_authorization_request', false)) {
                return $this->getResponseModeService($authorization->get('response_mode'));
            }
            throw $this->getExceptionManager()->getException(ExceptionManagerInterface::BAD_REQUEST, ExceptionManagerInterface::INVALID_REQUEST, 'The response mode parameter is not authorized.');
        }

        return $this->getResponseModeService($type->getResponseMode());
    }

    /**
     * @param string $mode
     *
     * @throws \OAuth2\Exception\BaseExceptionInterface
     *
     * @return \OAuth2\Endpoint\ResponseModeInterface
     */
    private function getResponseModeService($mode)
    {
        if (!array_key_exists($mode, $this->response_modes)) {
            throw $this->getExceptionManager()->getException(ExceptionManagerInterface::BAD_REQUEST, ExceptionManagerInterface::INVALID_REQUEST, sprintf('Unsupported response mode "%s".', $mode));
        }

        return $this->response_modes[$mode];
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
     */
    public function addResponseMode(ResponseModeInterface $response_mode)
    {
        $this->response_modes[$response_mode->getName()] = $response_mode;
    }
}
