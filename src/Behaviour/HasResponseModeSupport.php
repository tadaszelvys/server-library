<?php

/*
 * The MIT License (MIT)
 *
 * Copyright (c) 2014-2015 Spomky-Labs
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
    protected $response_modes = [];

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
        if (null !== $authorization->getResponseMode() && true === $this->getConfiguration()->get('allow_response_mode_parameter_in_authorization_request', false)) {
            // The client uses the response_mode parameter and the server allows it
            $mode = $authorization->getResponseMode();
        } elseif (null !== $multiple = $this->getResponseModeIfMultipleResponseTypes($authorization->getResponseType())) {
            // The response type contains multiple types defined by OpenID Connect Specification
            $mode = $multiple;
        } elseif (1 < count($types)) {
            // The response type contains multiple types but not defined by OpenID Connect Specification
            throw $this->getExceptionManager()->getException(ExceptionManagerInterface::INTERNAL_SERVER_ERROR, ExceptionManagerInterface::SERVER_ERROR, sprintf('The response mode "%s" is not supported.', $authorization->getResponseType()));
        } else {
            // The response type contains only one type
            $mode = $types[0]->getResponseMode();
        }

        if (!array_key_exists($mode, $this->response_modes)) {
            throw $this->getExceptionManager()->getException(ExceptionManagerInterface::INTERNAL_SERVER_ERROR, ExceptionManagerInterface::SERVER_ERROR, sprintf('Unable to retrieve response mode for response type "%s".', $authorization->getResponseType()));
        }

        return $this->response_modes[$mode];
    }

    /**
     * @param string $response_type
     *
     * @return null|string
     */
    public function getResponseModeIfMultipleResponseTypes($response_type)
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
     *
     * @return self
     */
    public function addResponseMode(ResponseModeInterface $response_mode)
    {
        $this->response_modes[$response_mode->getName()] = $response_mode;

        return $this;
    }
}
