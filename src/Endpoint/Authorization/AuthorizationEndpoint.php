<?php

/*
 * The MIT License (MIT)
 *
 * Copyright (c) 2014-2016 Spomky-Labs
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file for details.
 */

namespace OAuth2\Endpoint\Authorization;

use OAuth2\Behaviour\HasExceptionManager;
use OAuth2\Behaviour\HasScopeManager;
use OAuth2\Endpoint\Authorization\PreConfiguredAuthorization\PreConfiguredAuthorizationInterface;
use OAuth2\Endpoint\Authorization\PreConfiguredAuthorization\PreConfiguredAuthorizationManagerInterface;
use OAuth2\Exception\BaseExceptionInterface;
use OAuth2\Exception\ExceptionManagerInterface;
use OAuth2\Scope\ScopeManagerInterface;
use OAuth2\User\UserInterface;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Zend\Diactoros\Response;

abstract class AuthorizationEndpoint implements AuthorizationEndpointInterface
{
    use HasExceptionManager;
    use HasScopeManager;

    /**
     * @var \OAuth2\Endpoint\Authorization\AuthorizationFactoryInterface
     */
    private $authorization_factory;

    /**
     * @var \OAuth2\Endpoint\Authorization\PreConfiguredAuthorization\PreConfiguredAuthorizationManagerInterface|null
     */
    private $pre_configured_authorization_manager;

    /**
     * AuthorizationEndpoint constructor.
     *
     * @param \OAuth2\Endpoint\Authorization\AuthorizationFactoryInterface                                              $authorization_factory
     * @param \OAuth2\Scope\ScopeManagerInterface                                                                       $scope_manager
     * @param \OAuth2\Exception\ExceptionManagerInterface                                                               $exception_manager
     * @param \OAuth2\Endpoint\Authorization\PreConfiguredAuthorization\PreConfiguredAuthorizationManagerInterface|null $pre_configured_authorization_manager
     */
    public function __construct(
        AuthorizationFactoryInterface $authorization_factory,
        ScopeManagerInterface $scope_manager,
        ExceptionManagerInterface $exception_manager,
        PreConfiguredAuthorizationManagerInterface $pre_configured_authorization_manager = null
    ) {
        $this->authorization_factory = $authorization_factory;
        $this->pre_configured_authorization_manager = $pre_configured_authorization_manager;
        $this->setExceptionManager($exception_manager);
        $this->setScopeManager($scope_manager);
    }

    /**
     * @return \OAuth2\User\UserInterface|null
     */
    abstract protected function getCurrentUser();

    /**
     * @return bool
     */
    abstract protected function isCurrentUserFullyAuthenticated();

    /**
     * @param \Psr\Http\Message\ResponseInterface $response
     */
    abstract protected function redirectToLoginPage(ResponseInterface &$response);

    /**
     * @param \OAuth2\Endpoint\Authorization\AuthorizationInterface $authorization
     * @param \Psr\Http\Message\ServerRequestInterface              $request
     * @param \Psr\Http\Message\ResponseInterface                   $response
     */
    abstract protected function processConsentScreen(AuthorizationInterface $authorization, ServerRequestInterface $request, ResponseInterface &$response);

    /**
     * {@inheritdoc}
     */
    public function authorize(ServerRequestInterface $request, ResponseInterface &$response)
    {
        $authorization = $this->prepareAuthorization($request, $response);
        
        if (null === $authorization) {
            return;
        }

        $user = $this->getCurrentUser();
        //If User is null
            //If prompt none => error login required
            //If login => login
            //If consent => login
            //If select_account => login
        //If Use is logged in
            //If prompt none => continue
            //If login => login if not fully authenticated
            //If consent => continue
            //If select_account => continue
        if ($user instanceof UserInterface) {
            if ($authorization->hasPrompt('login') && !$this->isCurrentUserFullyAuthenticated()) {
                $this->redirectToLoginPage($response);
                
                return;
            }
        } else {
            if ($authorization->hasPrompt('none')) {
                $this->createRedirectionException(
                    $authorization,
                    $response,
                    ExceptionManagerInterface::LOGIN_REQUIRED
                );

                return;
            }
            $this->redirectToLoginPage($response);
            
            return;
        }
        $authorization->setUser($user);

        //Pre configured consent exist
            //If prompt none => continue
            //If login => continue
            //If consent => consent
            //If select_account => continue
        //Pre configured consent does not exist
            //If prompt none => error interaction required
            //If login => consent
            //If consent => consent
            //If select_account => consent
        $pre_configured_authorization = $this->tryToFindPreConfiguredAuthorization($authorization);
        if ($pre_configured_authorization instanceof PreConfiguredAuthorizationInterface) {
            if ($authorization->hasPrompt('consent')) {
                //Show consent screen

                $this->processConsentScreen($authorization, $request, $response);
                
                return;
            }
            $authorization->setAuthorized(true);
            $this->processAuthorization($authorization, $response);

            return;
        } else {
            if ($authorization->hasPrompt('none')) {
                $this->createRedirectionException(
                    $authorization,
                    $response,
                    ExceptionManagerInterface::INTERACTION_REQUIRED
                );

                return;
            }
            
            $this->processConsentScreen($authorization, $request, $response);

            return;
        }
    }

    /**
     * @param \Psr\Http\Message\ServerRequestInterface $request
     * @param \Psr\Http\Message\ResponseInterface      $response
     *
     * @return \OAuth2\Endpoint\Authorization\AuthorizationInterface
     */
    protected function prepareAuthorization(ServerRequestInterface $request, ResponseInterface &$response)
    {
        try {
            return $this->authorization_factory->createAuthorizationFromRequest($request);
        } catch (BaseExceptionInterface $e) {
            // FIXME: Try to redirect if possible
            $e->getHttpResponse($response);
        }
    }

    /**
     * @param \OAuth2\Endpoint\Authorization\AuthorizationInterface $authorization
     * @param \Psr\Http\Message\ResponseInterface                   $response
     */
    protected function processAuthorization(AuthorizationInterface $authorization, ResponseInterface &$response)
    {
        if ($authorization->isAuthorized() === false) {
            $this->createRedirectionException(
                $authorization,
                $response,
                ExceptionManagerInterface::ACCESS_DENIED,
                'The resource owner denied access to your client'
            );

            return;
        }

        $response_parameters = [];
        foreach ($authorization->getResponseTypes() as $type) {
            $response_parameters = array_merge(
                $response_parameters,
                $type->prepareAuthorization($authorization)
            );
        }
        if ($authorization->hasQueryParam(('state'))) {
            $response_parameters['state'] = $authorization->getQueryParam('state');
        }
        foreach ($authorization->getResponseTypes() as $type) {
            $type->finalizeAuthorization($response_parameters, $authorization, $authorization->getRedirectUri());
        }

        $authorization->getResponseMode()->prepareResponse($authorization->getRedirectUri(), $response_parameters, $response);
    }

    /**
     * @param \OAuth2\Endpoint\Authorization\AuthorizationInterface $authorization
     *
     * @return null|\OAuth2\Endpoint\Authorization\PreConfiguredAuthorization\PreConfiguredAuthorizationInterface
     */
    private function tryToFindPreConfiguredAuthorization(AuthorizationInterface $authorization)
    {
        if (null !== $this->pre_configured_authorization_manager) {

            return $this->pre_configured_authorization_manager->findOnePreConfiguredAuthorization(
                $authorization->getUser()->getPublicId(),
                $authorization->getClient()->getPublicId(),
                $authorization->getScopes()
            );
        }
    }

    /**
     * @param \OAuth2\Endpoint\Authorization\AuthorizationInterface $authorization
     * @param \Psr\Http\Message\ResponseInterface                   $response
     * @param string                                                $error
     * @param string|null                                           $error_description
     */
    private function createRedirectionException(AuthorizationInterface $authorization, ResponseInterface &$response, $error, $error_description = null)
    {
        $params = [
            'response_mode' => $authorization->getResponseMode(),
            'redirect_uri'   => $authorization->getRedirectUri(),
        ];
        if (true === $authorization->hasQueryParam('state')) {
            $params['state'] = $authorization->getQueryParam('state');
        }
        $exception = $this->getExceptionManager()->getRedirectException($error, $error_description, $params);
        $exception->getHttpResponse($response);
    }
}
