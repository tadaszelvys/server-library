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

use Assert\Assertion;
use OAuth2\Behaviour\HasExceptionManager;
use OAuth2\Behaviour\HasUserAccountManager;
use OAuth2\Endpoint\Authorization\AuthorizationEndpointExtension\AuthorizationEndpointExtensionInterface;
use OAuth2\Endpoint\Authorization\AuthorizationEndpointExtension\StateParameterExtension;
use OAuth2\Endpoint\Authorization\PreConfiguredAuthorization\PreConfiguredAuthorizationInterface;
use OAuth2\Endpoint\Authorization\PreConfiguredAuthorization\PreConfiguredAuthorizationManagerInterface;
use OAuth2\Exception\BaseExceptionInterface;
use OAuth2\Exception\ExceptionManagerInterface;
use OAuth2\OpenIdConnect\HasIdTokenManager;
use OAuth2\OpenIdConnect\IdTokenManagerInterface;
use OAuth2\ResponseMode\QueryResponseMode;
use OAuth2\UserAccount\UserAccountInterface;
use OAuth2\UserAccount\UserAccountManagerInterface;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;

abstract class AuthorizationEndpoint implements AuthorizationEndpointInterface
{
    use HasExceptionManager;
    use HasIdTokenManager;
    use HasUserAccountManager;

    /**
     * @var \OAuth2\Endpoint\Authorization\AuthorizationEndpointExtension\AuthorizationEndpointExtensionInterface[]
     */
    private $extensions = [];

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
     * @param \OAuth2\Endpoint\Authorization\PreConfiguredAuthorization\PreConfiguredAuthorizationManagerInterface $pre_configured_authorization_manager
     */
    public function enablePreConfiguredAuthorizationSupport(PreConfiguredAuthorizationManagerInterface $pre_configured_authorization_manager)
    {
        $this->pre_configured_authorization_manager = $pre_configured_authorization_manager;
    }

    /**
     * @param \OAuth2\OpenIdConnect\IdTokenManagerInterface $id_token_manager
     */
    public function enableIdTokenSupport(IdTokenManagerInterface $id_token_manager)
    {
        $this->setIdTokenManager($id_token_manager);
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
        $authorization = $this->prepareAuthorization($request, $response);

        if (null === $authorization) {
            return;
        }

        $user_account = $this->getCurrentUserAccount();

        // The query parameter 'id_token_hint' and the Id Token Manager are set
        if ($authorization->hasQueryParam('id_token_hint') && null !== $this->getIdTokenManager()) {
            try {
                $id_token_hint = $this->getIdTokenManager()->loadIdToken($authorization->getQueryParam('id_token_hint'));
                Assertion::true($id_token_hint->hasClaim('sub'), 'Invalid "id_token_hint" parameter.');
                $public_id = $this->getIdTokenManager()->getPublicIdFromSubjectIdentifier($id_token_hint->getClaim('sub'));
                Assertion::notNull($public_id, 'Invalid "id_token_hint" parameter.');
                if (null === $user_account) {
                    $user_account = $this->getUserAccountManager()->getUserAccountByPublicId($public_id);
                } else {
                    if ($user_account->getPublicId() !== $public_id) {
                        $this->redirectToLoginPage($authorization, $request, $response);

                        return;
                    }
                }
            } catch (\Exception $e) {
                $this->createRedirectionException($authorization, $response, ExceptionManagerInterface::BAD_REQUEST, $e->getMessage());

                return;
            }
        }

        //If UserAccount is logged in
        if ($user_account instanceof UserAccountInterface) {
            // Whatever the prompt is, if the max_age constraint is not satisfied, the user is redirected to the login page
            if ($authorization->hasQueryParam('max_age') && time() - $user_account->getLastLoginAt() > $authorization->getQueryParam('max_age')) {
                $this->redirectToLoginPage($authorization, $request, $response);

                return;
            }
            //If prompt=login => login required
            if ($authorization->hasPrompt('login') && !$this->isCurrentUserFullyAuthenticated()) {
                $this->redirectToLoginPage($authorization, $request, $response);

                return;
            }
            //If prompt=none => continue
            //If prompt=consent => continue
            //If prompt=select_account => continue
        } else { //If UserAccount is null
            //If prompt=none => error login required
            if ($authorization->hasPrompt('none')) {
                $this->createRedirectionException($authorization, $response, ExceptionManagerInterface::LOGIN_REQUIRED);

                return;
            }
            //If prompt=login => login
            //If prompt=consent => login
            //If prompt=select_account => login
            $this->redirectToLoginPage($authorization, $request, $response);

            return;
        }
        $authorization->setUserAccount($user_account);

        $pre_configured_authorization = $this->findPreConfiguredAuthorization($authorization);
        //Pre configured consent exist
        if ($pre_configured_authorization instanceof PreConfiguredAuthorizationInterface) {
            //If prompt=consent => consent
            if ($authorization->hasPrompt('consent')) {
                //Show consent screen

                $this->processConsentScreen($authorization, $request, $response);

                return;
            }
            //If prompt=none => continue
            //If prompt=login => continue
            //If prompt=select_account => continue
            $authorization->setAuthorized(true);
            $this->processAuthorization($request, $response, $authorization);

            return;
        } else { //Pre configured consent does not exist
            //If prompt=prompt none => error interaction required
            if ($authorization->hasPrompt('none')) {
                $this->createRedirectionException($authorization, $response, ExceptionManagerInterface::INTERACTION_REQUIRED);

                return;
            }

            //If prompt=login => consent
            //If prompt=consent => consent
            //If prompt=select_account => consent
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

                $e2 = $this->getExceptionManager()->getRedirectException(
                    $e->getMessage(),
                    $e->getDescription(),
                    $data
                );
                $e2->getHttpResponse($response);
            } else {
                $e->getHttpResponse($response);
            }
        }
    }

    /**
     * @param \Psr\Http\Message\ServerRequestInterface              $request
     * @param \Psr\Http\Message\ResponseInterface                   $response
     * @param \OAuth2\Endpoint\Authorization\AuthorizationInterface $authorization
     */
    protected function processAuthorization(ServerRequestInterface $request, ResponseInterface &$response, AuthorizationInterface $authorization)
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
        foreach ($authorization->getResponseTypes() as $type) {
            $type->finalizeAuthorization($response_parameters, $authorization, $authorization->getRedirectUri());
        }
        foreach ($this->extensions as $extension) {
            $extension->process($response_parameters, $request, $response, $authorization);
        }

        $authorization->getResponseMode()->prepareResponse($authorization->getRedirectUri(), $response_parameters, $response);
    }

    /**
     * @param \OAuth2\Endpoint\Authorization\AuthorizationInterface $authorization
     *
     * @return null|\OAuth2\Endpoint\Authorization\PreConfiguredAuthorization\PreConfiguredAuthorizationInterface
     */
    private function findPreConfiguredAuthorization(AuthorizationInterface $authorization)
    {
        if (null !== $this->getPreConfiguredAuthorizationManager()) {
            return $this->getPreConfiguredAuthorizationManager()->findOnePreConfiguredAuthorization(
                $authorization->getUserAccount()->getUserPublicId(),
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
     * @return null|\OAuth2\Endpoint\Authorization\PreConfiguredAuthorization\PreConfiguredAuthorizationManagerInterface
     */
    protected function getPreConfiguredAuthorizationManager()
    {
        return $this->pre_configured_authorization_manager;
    }
}
