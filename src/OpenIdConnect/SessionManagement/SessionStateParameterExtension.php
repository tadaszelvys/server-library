<?php

/*
 * The MIT License (MIT)
 *
 * Copyright (c) 2014-2016 Spomky-Labs
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file for details.
 */

namespace OAuth2\OpenIdConnect\SessionManagement;

use OAuth2\Endpoint\Authorization\AuthorizationEndpointExtension\AuthorizationEndpointExtensionInterface;
use OAuth2\Endpoint\Authorization\AuthorizationInterface;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;

abstract class SessionStateParameterExtension implements AuthorizationEndpointExtensionInterface
{
    /**
     * {@inheritdoc}
     */
    public function process(array &$response_parameters, ServerRequestInterface $request, ResponseInterface &$response, AuthorizationInterface $authorization)
    {
        if (!$authorization->hasScope('openid')) {
            return;
        }
        
        $browser_state = $this->getBrowserState($request);
        if (null === $browser_state) {
            $browser_state = $this->generateBrowserState();
            $this->saveBrowserState($response, $browser_state);
        }
        
        $session_state = $this->calculateSessionState($request, $authorization, $browser_state);
        $response_parameters['session_state'] = $session_state;
    }

    /**
     * @param \Psr\Http\Message\ServerRequestInterface $request
     *
     * @return string|null
     */
    abstract function getBrowserState(ServerRequestInterface $request);

    /**
     * @param \Psr\Http\Message\ResponseInterface $response
     * @param string                              $browser_state
     */
    abstract protected function saveBrowserState(ResponseInterface &$response, $browser_state);

    /**
     * @return string
     */
    abstract protected function generateBrowserState();

    /**
     * @param \Psr\Http\Message\ServerRequestInterface              $request
     * @param \OAuth2\Endpoint\Authorization\AuthorizationInterface $authorization
     * @param string                                                $browser_state
     *
     * @return string
     */
    abstract protected function calculateSessionState(ServerRequestInterface $request, AuthorizationInterface $authorization, $browser_state);
}
