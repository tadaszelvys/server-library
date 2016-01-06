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
     * @param \OAuth2\Grant\ResponseTypeSupportInterface[] $types
     * @param \OAuth2\Endpoint\Authorization               $authorization
     *
     * @throws \OAuth2\Exception\BaseExceptionInterface
     *
     * @return \OAuth2\Endpoint\ResponseModeInterface
     */
    public function getResponseMode(array $types, Authorization $authorization)
    {
        if ($authorization->has('response_mode')) {
            if ($this->getConfiguration()->get('allow_response_mode_parameter_in_authorization_request', false)) {
                return $this->getResponseModeService($authorization->get('response_mode'));
            }
            throw $this->getExceptionManager()->getException(ExceptionManagerInterface::BAD_REQUEST, ExceptionManagerInterface::INVALID_REQUEST, 'The response mode parameter is not authorized.');
        }
        if (null !== $mode = $this->getResponseModeIfMultipleResponseTypes($authorization->get('response_type'))) {
            return $this->getResponseModeService($mode);
        }
        if (1 === count($types)) {
            return $this->getResponseModeService($types[0]->getResponseMode());
        }
        throw $this->getExceptionManager()->getException(ExceptionManagerInterface::BAD_REQUEST, ExceptionManagerInterface::INVALID_REQUEST, sprintf('Unable to retrieve response mode for response type "%s".', $authorization->get('response_type')));
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
     * @param string $response_type
     *
     * @return null|string
     */
    private function getResponseModeIfMultipleResponseTypes($response_type)
    {
        switch ($response_type) {
            case 'code token':
            case 'code id_token':
            case 'id_token token':
            case 'code id_token token':
                return 'fragment';
            default:
                return;
        }
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
