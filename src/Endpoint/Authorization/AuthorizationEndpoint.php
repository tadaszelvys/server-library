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
use OAuth2\Behaviour\HasUserAccountManager;
use OAuth2\Endpoint\Authorization\Extension\AuthorizationEndpointExtensionInterface;
use OAuth2\Endpoint\Authorization\Extension\StateParameterExtension;
use OAuth2\Exception\BaseExceptionInterface;
use OAuth2\Exception\ExceptionManagerInterface;
use OAuth2\ResponseMode\QueryResponseMode;
use OAuth2\UserAccount\UserAccountInterface;
use OAuth2\UserAccount\UserAccountManagerInterface;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;

abstract class AuthorizationEndpoint implements AuthorizationEndpointInterface
{
    use HasExceptionManager;
    use HasUserAccountManager;

    /**
     * @var \OAuth2\Endpoint\Authorization\Extension\AuthorizationEndpointExtensionInterface[]
     */
    private $extensions = [];

    /**
     * @var \OAuth2\Endpoint\Authorization\AuthorizationFactoryInterface
     */
    private $authorization_factory;

    /**
     * AuthorizationEndpoint constructor.
     *
     * @param \OAuth2\UserAccount\UserAccountManagerInterface              $user_account_manager
     * @param \OAuth2\Endpoint\Authorization\AuthorizationFactoryInterface $authorization_factory
     * @param \OAuth2\Exception\ExceptionManagerInterface                  $exception_manager
     */
    public function __construct(UserAccountManagerInterface $user_account_manager, AuthorizationFactoryInterface $authorization_factory, ExceptionManagerInterface $exception_manager)
    {
        $this->authorization_factory = $authorization_factory;
        $this->setUserAccountManager($user_account_manager);
        $this->setExceptionManager($exception_manager);
        $this->addExtension(new StateParameterExtension());
    }

    /**
     * @return \OAuth2\UserAccount\UserAccountInterface|null
     */
    abstract protected function getCurrentUserAccount();

    /**
     * @return bool
     */
    abstract protected function isCurrentUserFullyAuthenticated();

    /**
     * @param \OAuth2\Endpoint\Authorization\AuthorizationInterface $authorization
     * @param \Psr\Http\Message\ServerRequestInterface              $request
     * @param \Psr\Http\Message\ResponseInterface                   $response
     */
    abstract protected function redirectToLoginPage(AuthorizationInterface $authorization, ServerRequestInterface $request, ResponseInterface &$response);

    /**
     * @param \OAuth2\Endpoint\Authorization\AuthorizationInterface $authorization
     * @param \Psr\Http\Message\ServerRequestInterface              $request
     * @param \Psr\Http\Message\ResponseInterface                   $response
     */
    abstract protected function processConsentScreen(AuthorizationInterface $authorization, ServerRequestInterface $request, ResponseInterface &$response);

    /**
     * {@inheritdoc}
     */
    public function addExtension(AuthorizationEndpointExtensionInterface $extension)
    {
        $this->extensions[] = $extension;
    }

    /**
     * {@inheritdoc}
     */
    public function authorize(ServerRequestInterface $request, ResponseInterface &$response)
    {
        try {
            $this->allProcess($request, $response);
        } catch (Exception\AuthorizeException $e) {
            $this->processAuthorization($request, $response, $e->getAuthorization());
        } catch (Exception\CreateRedirectionException $e) {
            $this->createRedirectionException($e->getAuthorization(), $response, $e->getMessage(), $e->getDescription());
        } catch (Exception\ShowConsentScreenException $e) {
            $this->processConsentScreen($e->getAuthorization(), $request, $response);
        } catch (Exception\RedirectToLoginPageException $e) {
            $this->redirectToLoginPage($e->getAuthorization(), $request, $response);
        } catch (Exception\AuthorizationException $e) {
            //Nothing to do. This means an exception or one of the methods populated the response.
        }
    }

    /**
     * @param \Psr\Http\Message\ServerRequestInterface $request
     * @param \Psr\Http\Message\ResponseInterface      $response
     *
     * @throws \Exception
     */
    protected function allProcess(ServerRequestInterface $request, ResponseInterface &$response)
    {
        $authorization = $this->prepareAuthorization($request, $response);
        $user_account = $this->getCurrentUserAccount();
        $this->processUserAccount($request, $response, $authorization, $user_account);

        if (null !== $user_account) {
            $this->processUserAccountIsAvailable($user_account, $this->isCurrentUserFullyAuthenticated(), $request, $response, $authorization);
        } else {
            $this->processUserAccountIsNotAvailable($request, $response, $authorization);

            throw new Exception\RedirectToLoginPageException($authorization);
        }
        $authorization->setUserAccount($user_account);
        $this->processAfterUserAccountComputation($user_account, $this->isCurrentUserFullyAuthenticated(), $request, $response, $authorization);

        throw new Exception\ShowConsentScreenException($authorization);
    }

    /**
     * @param \Psr\Http\Message\ServerRequestInterface $request
     * @param \Psr\Http\Message\ResponseInterface      $response
     *
     * @throws \OAuth2\Endpoint\Authorization\Exception\AuthorizationException
     *
     * @return \OAuth2\Endpoint\Authorization\AuthorizationInterface
     */
    protected function prepareAuthorization(ServerRequestInterface $request, ResponseInterface &$response)
    {
        try {
            return $this->authorization_factory->createAuthorizationFromRequest($request);
        } catch (BaseExceptionInterface $e) {
            $params = $request->getQueryParams();
            if (array_key_exists('redirect_uri', $params)) {
                if (array_key_exists('response_type', $params)) {
                    try {
                        $types = $this->authorization_factory->getResponseTypes($params);
                        $response_mode = $this->authorization_factory->getResponseMode($params, $types);
                    } catch (\Exception $e) {
                        $response_mode = new QueryResponseMode();
                    }
                } else {
                    $response_mode = new QueryResponseMode();
                }
                $data = [
                    'redirect_uri'  => $params['redirect_uri'],
                    'response_mode' => $response_mode,
                ];
                if (array_key_exists('state', $params)) {
                    $data['state'] = $params['state'];
                }

                $e2 = $this->getExceptionManager()->getRedirectException($e->getMessage(), $e->getDescription(), $data);
                $e2->getHttpResponse($response);
            } else {
                $e->getHttpResponse($response);
            }
        }
        throw new Exception\AuthorizationException();
    }

    /**
     * @param \Psr\Http\Message\ServerRequestInterface              $request
     * @param \Psr\Http\Message\ResponseInterface                   $response
     * @param \OAuth2\Endpoint\Authorization\AuthorizationInterface $authorization
     *
     * @throws \OAuth2\Endpoint\Authorization\Exception\CreateRedirectionException
     */
    protected function processAuthorization(ServerRequestInterface $request, ResponseInterface &$response, AuthorizationInterface $authorization)
    {
        if ($authorization->isAuthorized() === false) {
            $this->createRedirectionException($authorization, $response, ExceptionManagerInterface::ACCESS_DENIED, 'The resource owner denied access to your client');

            return;
        }

        $response_parameters = $this->computeResponseParameters($authorization);
        $this->process($response_parameters, $request, $response, $authorization);
        $authorization->getResponseMode()->prepareResponse($authorization->getRedirectUri(), $response_parameters, $response);
    }

    /**
     * @param \OAuth2\Endpoint\Authorization\AuthorizationInterface $authorization
     *
     * @return array
     */
    private function computeResponseParameters(AuthorizationInterface $authorization)
    {
        $response_parameters = [];
        foreach ($authorization->getResponseTypes() as $type) {
            $response_parameters = array_merge($response_parameters, $type->prepareAuthorization($authorization));
        }
        foreach ($authorization->getResponseTypes() as $type) {
            $type->finalizeAuthorization($response_parameters, $authorization, $authorization->getRedirectUri());
        }

        return $response_parameters;
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
            'response_mode'  => $authorization->getResponseMode(),
            'redirect_uri'   => $authorization->getRedirectUri(),
        ];
        if (true === $authorization->hasQueryParam('state')) {
            $params['state'] = $authorization->getQueryParam('state');
        }
        $exception = $this->getExceptionManager()->getRedirectException($error, $error_description, $params);
        $exception->getHttpResponse($response);
    }

    /**
     * @param \Psr\Http\Message\ServerRequestInterface              $request
     * @param \Psr\Http\Message\ResponseInterface                   $response
     * @param \OAuth2\Endpoint\Authorization\AuthorizationInterface $authorization
     * @param \OAuth2\UserAccount\UserAccountInterface|null         $user_account
     */
    public function processUserAccount(ServerRequestInterface $request, ResponseInterface &$response, AuthorizationInterface $authorization, UserAccountInterface &$user_account = null)
    {
        foreach ($this->extensions as $extension) {
            $extension->processUserAccount($request, $response, $authorization, $user_account);
        }
    }

    /**
     * @param array                                                 $response_parameters
     * @param \Psr\Http\Message\ServerRequestInterface              $request
     * @param \Psr\Http\Message\ResponseInterface                   $response
     * @param \OAuth2\Endpoint\Authorization\AuthorizationInterface $authorization
     */
    private function process(array &$response_parameters, ServerRequestInterface $request, ResponseInterface &$response, AuthorizationInterface $authorization)
    {
        foreach ($this->extensions as $extension) {
            $extension->process($response_parameters, $request, $response, $authorization);
        }
    }

    /**
     * @param \OAuth2\UserAccount\UserAccountInterface              $user_account
     * @param bool                                                  $is_fully_authenticated
     * @param \Psr\Http\Message\ServerRequestInterface              $request
     * @param \Psr\Http\Message\ResponseInterface                   $response
     * @param \OAuth2\Endpoint\Authorization\AuthorizationInterface $authorization
     */
    private function processUserAccountIsAvailable(UserAccountInterface $user_account, $is_fully_authenticated, ServerRequestInterface $request, ResponseInterface $response, AuthorizationInterface $authorization)
    {
        foreach ($this->extensions as $extension) {
            $extension->processUserAccountIsAvailable($user_account, $is_fully_authenticated, $request, $response, $authorization);
        }
    }

    /**
     * @param \Psr\Http\Message\ServerRequestInterface              $request
     * @param \Psr\Http\Message\ResponseInterface                   $response
     * @param \OAuth2\Endpoint\Authorization\AuthorizationInterface $authorization
     */
    private function processUserAccountIsNotAvailable(ServerRequestInterface $request, ResponseInterface $response, AuthorizationInterface $authorization)
    {
        foreach ($this->extensions as $extension) {
            $extension->processUserAccountIsNotAvailable($request, $response, $authorization);
        }
    }

    /**
     * @param \OAuth2\UserAccount\UserAccountInterface              $user_account
     * @param bool                                                  $is_fully_authenticated
     * @param \Psr\Http\Message\ServerRequestInterface              $request
     * @param \Psr\Http\Message\ResponseInterface                   $response
     * @param \OAuth2\Endpoint\Authorization\AuthorizationInterface $authorization
     */
    private function processAfterUserAccountComputation(UserAccountInterface $user_account, $is_fully_authenticated, ServerRequestInterface $request, ResponseInterface $response, AuthorizationInterface $authorization)
    {
        foreach ($this->extensions as $extension) {
            $extension->processAfterUserAccountComputation($user_account, $is_fully_authenticated, $request, $response, $authorization);
        }
    }
}
