<?php

namespace OAuth2\Grant;

use OAuth2\Behaviour\HasExceptionManager;
use OAuth2\Client\ClientInterface;
use OAuth2\Client\ConfidentialClientInterface;
use OAuth2\Endpoint\Authorization;
use OAuth2\Exception\ExceptionManagerInterface;
use OAuth2\Token\AuthCodeInterface;
use OAuth2\Token\AuthCodeManagerInterface;
use OAuth2\Util\RequestBody;
use Psr\Http\Message\ServerRequestInterface;

final class AuthorizationCodeGrantType implements ResponseTypeSupportInterface, GrantTypeSupportInterface
{
    use HasExceptionManager;
    /**
     * @var\OAuth2\Token\AuthCodeManagerInterface
     */
    protected $auth_code_manager;

    /**
     * @return \OAuth2\Token\AuthCodeManagerInterface
     */
    protected function getAuthCodeManager()
    {
        return $this->auth_code_manager;
    }

    /**
     * @param \OAuth2\Token\AuthCodeManagerInterface $auth_code_manager
     *
     * @return self
     */
    public function setAuthCodeManager(AuthCodeManagerInterface $auth_code_manager)
    {
        $this->auth_code_manager = $auth_code_manager;

        return $this;
    }

    /**
     * {@inheritdoc}
     */
    public function getResponseType()
    {
        return 'code';
    }

    /**
     * {@inheritdoc}
     */
    public function getResponseMode()
    {
        return 'query';
    }

    /**
     * {@inheritdoc}
     */
    public function grantAuthorization(Authorization $authorization)
    {
        $code = $this->getAuthCodeManager()->createAuthCode($authorization->getClient(), $authorization->getEndUser(), $authorization->getQueryParams(), $authorization->getRedirectUri(), $authorization->getScope(), $authorization->getIssueRefreshToken());
        $params = [
            'code' => $code->getToken(),
        ];
        if (null !== $authorization->getState()) {
            $params['state'] = $authorization->getState();
        }

        return $params;
    }

    /**
     * {@inheritdoc}
     */
    public function getGrantType()
    {
        return 'authorization_code';
    }

    /**
     * {@inheritdoc}
     */
    public function prepareGrantTypeResponse(ServerRequestInterface $request, GrantTypeResponseInterface &$grant_type_response)
    {
        //Nothing to do
    }

    /**
     * {@inheritdoc}
     */
    public function grantAccessToken(ServerRequestInterface $request, ClientInterface $client, GrantTypeResponseInterface &$grant_type_response)
    {
        $this->checkClient($request, $client);
        $authCode = $this->getAuthCode($request);

        if (!$authCode instanceof AuthCodeInterface) {
            throw $this->getExceptionManager()->getException(ExceptionManagerInterface::BAD_REQUEST, ExceptionManagerInterface::INVALID_GRANT, "Code doesn't exist or is invalid for the client.");
        }

        $this->checkAuthCode($authCode, $client);

        $redirect_uri = RequestBody::getParameter($request, 'redirect_uri');

        // Validate the redirect URI.
        $this->checkRedirectUri($authCode, $redirect_uri);

        $this->getAuthCodeManager()->markAuthCodeAsUsed($authCode);

        $grant_type_response->setRequestedScope(RequestBody::getParameter($request, 'scope') ?: $authCode->getScope())
            ->setAvailableScope($authCode->getScope())
            ->setResourceOwnerPublicId($authCode->getResourceOwnerPublicId())
            ->setRefreshTokenIssued($authCode->getIssueRefreshToken())
            ->setRefreshTokenScope($authCode->getScope())
            ->setRefreshTokenRevoked(null);
    }

    /**
     * @param \Psr\Http\Message\ServerRequestInterface $request
     *
     * @throws \OAuth2\Exception\BaseExceptionInterface
     *
     * @return null|\OAuth2\Token\AuthCodeInterface
     */
    protected function getAuthCode(ServerRequestInterface $request)
    {
        $code = RequestBody::getParameter($request, 'code');
        if (null === $code) {
            throw $this->getExceptionManager()->getException(ExceptionManagerInterface::BAD_REQUEST, ExceptionManagerInterface::INVALID_REQUEST, 'Missing parameter. "code" is required.');
        }

        return $this->getAuthCodeManager()->getAuthCode($code);
    }

    /**
     * @param \Psr\Http\Message\ServerRequestInterface $request
     * @param \OAuth2\Client\ClientInterface           $client
     *
     * @throws \OAuth2\Exception\BaseExceptionInterface
     */
    protected function checkClient(ServerRequestInterface $request, ClientInterface $client)
    {
        if (!$client instanceof ConfidentialClientInterface) {
            if (null === ($client_id = RequestBody::getParameter($request, 'client_id')) || $client_id !== $client->getPublicId()) {
                throw $this->getExceptionManager()->getException(ExceptionManagerInterface::BAD_REQUEST, ExceptionManagerInterface::INVALID_REQUEST, 'The client_id parameter is required for non-confidential clients.');
            }
        }
    }

    /**
     * @param \OAuth2\Token\AuthCodeInterface $authCode
     * @param string                          $redirect_uri
     *
     * @throws \OAuth2\Exception\BaseExceptionInterface
     */
    protected function checkRedirectUri(AuthCodeInterface $authCode, $redirect_uri)
    {
        if (null !== $authCode->getRedirectUri() && $redirect_uri !== $authCode->getRedirectUri()) {
            throw $this->getExceptionManager()->getException(ExceptionManagerInterface::BAD_REQUEST, ExceptionManagerInterface::INVALID_REQUEST, 'The redirect URI is missing or does not match.');
        }
    }

    /**
     * @param \OAuth2\Token\AuthCodeInterface $authCode
     * @param \OAuth2\Client\ClientInterface  $client
     *
     * @throws \OAuth2\Exception\BaseExceptionInterface
     */
    protected function checkAuthCode(AuthCodeInterface $authCode, ClientInterface $client)
    {
        if ($client->getPublicId() !== $authCode->getClientPublicId()) {
            throw $this->getExceptionManager()->getException(ExceptionManagerInterface::BAD_REQUEST, ExceptionManagerInterface::INVALID_GRANT, "Code doesn't exist or is invalid for the client.");
        }

        if ($authCode->hasExpired()) {
            throw $this->getExceptionManager()->getException(ExceptionManagerInterface::BAD_REQUEST, ExceptionManagerInterface::INVALID_GRANT, 'The authorization code has expired.');
        }
    }
}