<?php

declare(strict_types=1);

/*
 * The MIT License (MIT)
 *
 * Copyright (c) 2014-2017 Spomky-Labs
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file for details.
 */

namespace OAuth2\Endpoint\Authorization;

use Interop\Http\ServerMiddleware\DelegateInterface;
use Interop\Http\ServerMiddleware\MiddlewareInterface;
use OAuth2\Endpoint\Authorization\Extension\AuthorizationEndpointExtensionInterface;
use OAuth2\Endpoint\Authorization\Extension\StateParameterExtension;
use OAuth2\Model\UserAccount\UserAccount;
use OAuth2\Response\OAuth2Exception;
use OAuth2\Response\OAuth2ResponseFactoryManagerInterface;
use OAuth2\ResponseMode\QueryResponseMode;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;

abstract class AuthorizationEndpoint implements MiddlewareInterface
{
    /**
     * @var AuthorizationEndpointExtensionInterface[]
     */
    private $extensions = [];

    /**
     * @var AuthorizationFactory
     */
    private $authorizationFactory;

    /**
     * AuthorizationEndpoint constructor.
     *
     * @param AuthorizationFactory $authorizationFactory
     */
    public function __construct(AuthorizationFactory $authorizationFactory)
    {
        $this->authorizationFactory = $authorizationFactory;
        $this->addExtension(new StateParameterExtension());
    }

    /**
     * @return UserAccount|null
     */
    abstract protected function getCurrentUserAccount();

    /**
     * @return bool
     */
    abstract protected function isCurrentUserFullyAuthenticated(): bool;

    /**
     * @param Authorization          $authorization
     * @param ServerRequestInterface $request
     *
     * @return ResponseInterface
     */
    abstract protected function redirectToLoginPage(Authorization $authorization, ServerRequestInterface $request): ResponseInterface;

    /**
     * @param Authorization          $authorization
     * @param ServerRequestInterface $request
     *
     * @return ResponseInterface
     */
    abstract protected function processConsentScreen(Authorization $authorization, ServerRequestInterface $request): ResponseInterface;

    /**
     * @param AuthorizationEndpointExtensionInterface $extension
     *
     * @return AuthorizationEndpoint
     */
    public function addExtension(AuthorizationEndpointExtensionInterface $extension): AuthorizationEndpoint
    {
        $this->extensions[] = $extension;

        return $this;
    }

    /**
     * {@inheritdoc}
     */
    public function process(ServerRequestInterface $request, DelegateInterface $delegate)
    {
        try {
            /**
             * Get the Authorization Object from the request.
             */
            $authorization = $this->authorizationFactory->createAuthorizationFromRequest($request);

            /**
             * Get the current user account
             * - The user is logged in and the account is available
             * - The user account is found by other means (ID Token).
             */
            $user_account = $this->getCurrentUserAccount();
            $this->processUserAccount($request, $authorization, $user_account);

            /*
             * Process
             * - If the user account is available
             *     - Verify it is fully authenticated
             *     - Modify the authorization object
             * - If the user account is not available
             *     - Redirect to the login page
             */
            if (null !== $user_account) {
                $this->processUserAccountIsAvailable($user_account, $this->isCurrentUserFullyAuthenticated(), $request, $authorization);
            } else {
                $this->processUserAccountIsNotAvailable($request, $authorization);

                return $this->redirectToLoginPage($authorization, $request);
                //throw new Exception\RedirectToLoginPageException($authorization);
            }
            $authorization->setUserAccount($user_account);
            /*
             * Process
             */
            $this->processAfterUserAccountComputation($user_account, $this->isCurrentUserFullyAuthenticated(), $request, $authorization);

            /*
             * Show the consent screen
             */
            return $this->processConsentScreen($authorization, $request);
        } catch (OAuth2Exception $e) {
            $params = $request->getQueryParams();
            if (array_key_exists('redirect_uri', $params)) {
                if (array_key_exists('response_type', $params)) {
                    try {
                        $types = $this->authorizationFactory->getResponseTypes($params);
                        $response_mode = $this->authorizationFactory->getResponseMode($params, $types);
                    } catch (\Exception $e) {
                        $response_mode = new QueryResponseMode();
                    }
                } else {
                    $response_mode = new QueryResponseMode();
                }
                $data = $e->getOAuth2Response()->getData();
                $data['redirect_uri'] = $params['redirect_uri'];
                $data['response_mode'] = $response_mode;
                if (array_key_exists('state', $params)) {
                    $data['state'] = $params['state'];
                }

                $e2 = $this->getResponseFactoryManager()->getResponse(302, $data);

                return $e2->getResponse();
            } else {
                return $e->getOAuth2Response()->getResponse();
            }
        } catch (Exception\AuthorizeException $e) {
            return $this->processAuthorization($request, $e->getAuthorization());
        } catch (Exception\CreateRedirectionException $e) {
            return $this->createRedirectionException($e->getAuthorization(), $e->getMessage(), $e->getDescription());
        } catch (Exception\ShowConsentScreenException $e) {
            $formData = $this->processConsentScreen($e->getAuthorization(), $request);
            $formData = $formData ?: [];
            $this->processAfterConsentScreenIsAccepted($e->getAuthorization(), $formData);
        } catch (Exception\RedirectToLoginPageException $e) {
            return $this->redirectToLoginPage($e->getAuthorization(), $request);
        } catch (Exception\AuthorizationException $e) {
            //Nothing to do. This means an exception or one of the methods populated the response.
        }
    }

    /**
     * @param Authorization $authorization
     */
    protected function checkAuthorization(Authorization $authorization)
    {
        $types = $authorization->getResponseTypes();
        foreach ($types as $type) {
            $type->checkAuthorization($authorization);
        }
    }

    /**
     * @param ServerRequestInterface $request
     * @param Authorization          $authorization
     *
     * @return ResponseInterface
     */
    protected function processAuthorization(ServerRequestInterface $request, Authorization $authorization): ResponseInterface
    {
        if ($authorization->isAuthorized() === false) {
            return $this->createRedirectionException($authorization, OAuth2ResponseFactoryManagerInterface::ERROR_ACCESS_DENIED, 'The resource owner denied access to your client');
        }

        $response_parameters = $this->computeResponseParameters($authorization);
        $this->process($response_parameters, $request, $authorization);

        return $authorization->getResponseMode()->prepareResponse($authorization->getRedirectUri(), $response_parameters);
    }

    /**
     * @param Authorization $authorization
     *
     * @return array
     */
    private function computeResponseParameters(Authorization $authorization): array
    {
        $response_parameters = [];
        foreach ($authorization->getResponseTypes() as $type) {
            $response_parameters = array_merge($response_parameters, $type->getAuthorization($authorization));
        }
        foreach ($authorization->getResponseTypes() as $type) {
            $type->finalizeAuthorization($response_parameters, $authorization, $authorization->getRedirectUri());
        }

        return $response_parameters;
    }

    /**
     * @param Authorization $authorization
     * @param string        $error
     * @param string|null   $error_description
     *
     * @return ResponseInterface
     */
    private function createRedirectionException(Authorization $authorization, $error, $error_description = null): ResponseInterface
    {
        $params = [
            'error'                      => $error,
            'error_description'          => $error_description,
            'response_mode'              => $authorization->getResponseMode(),
            'redirect_uri'               => $authorization->getRedirectUri(),
        ];
        if (true === $authorization->hasQueryParam('state')) {
            $params['state'] = $authorization->getQueryParam('state');
        }
        $exception = $this->getResponseFactoryManager()->getResponse(302, $params);

        return $exception->getResponse();
    }

    /**
     * @param ServerRequestInterface $request
     * @param Authorization          $authorization
     * @param UserAccount|null       $user_account
     */
    public function processUserAccount(ServerRequestInterface $request, Authorization $authorization, UserAccount &$user_account = null)
    {
        foreach ($this->extensions as $extension) {
            $extension->processUserAccount($request, $authorization, $user_account);
        }
    }

    /**
     * @param array                  $response_parameters
     * @param ServerRequestInterface $request
     * @param Authorization          $authorization
     */
    private function process(array &$response_parameters, ServerRequestInterface $request, Authorization $authorization)
    {
        foreach ($this->extensions as $extension) {
            $extension->process($response_parameters, $request, $authorization);
        }
    }

    /**
     * @param UserAccount            $user_account
     * @param bool                   $isFullyAuthenticated
     * @param ServerRequestInterface $request
     * @param Authorization          $authorization
     */
    private function processUserAccountIsAvailable(UserAccount $user_account, $isFullyAuthenticated, ServerRequestInterface $request, Authorization $authorization)
    {
        foreach ($this->extensions as $extension) {
            $extension->processUserAccountIsAvailable($user_account, $isFullyAuthenticated, $request, $authorization);
        }
    }

    /**
     * @param ServerRequestInterface $request
     * @param Authorization          $authorization
     */
    private function processUserAccountIsNotAvailable(ServerRequestInterface $request, Authorization $authorization)
    {
        foreach ($this->extensions as $extension) {
            $extension->processUserAccountIsNotAvailable($request, $authorization);
        }
    }

    /**
     * @param UserAccount            $user_account
     * @param bool                   $isFullyAuthenticated
     * @param ServerRequestInterface $request
     * @param Authorization          $authorization
     */
    private function processAfterUserAccountComputation(UserAccount $user_account, $isFullyAuthenticated, ServerRequestInterface $request, Authorization $authorization)
    {
        foreach ($this->extensions as $extension) {
            $extension->processAfterUserAccountComputation($user_account, $isFullyAuthenticated, $request, $authorization);
        }
    }

    /**
     * @param Authorization $authorization
     *
     * @return array
     */
    protected function processConsentScreenOptions(Authorization $authorization): array
    {
        $option = [];
        foreach ($this->extensions as $extension) {
            $extension->processConsentScreenOptions($authorization, $option);
        }

        return $option;
    }

    /**
     * @param Authorization $authorization
     * @param array         $formData
     */
    protected function processAfterConsentScreenIsAccepted(Authorization $authorization, array $formData)
    {
        foreach ($this->extensions as $extension) {
            $extension->processAfterConsentScreenIsAccepted($authorization, $formData);
        }
    }
}
