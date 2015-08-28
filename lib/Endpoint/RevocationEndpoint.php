<?php

namespace OAuth2\Endpoint;

use OAuth2\Behaviour\HasAccessTokenManager;
use OAuth2\Behaviour\HasClientManagerSupervisor;
use OAuth2\Behaviour\HasConfiguration;
use OAuth2\Behaviour\HasExceptionManager;
use OAuth2\Behaviour\HasRefreshTokenManager;
use OAuth2\Client\ClientInterface;
use OAuth2\Client\ConfidentialClientInterface;
use OAuth2\Exception\BaseException;
use OAuth2\Exception\BaseExceptionInterface;
use OAuth2\Exception\ExceptionManagerInterface;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Util\RequestBody;

class RevocationEndpoint implements RevocationEndpointInterface
{
    use HasConfiguration;
    use HasExceptionManager;
    use HasClientManagerSupervisor;
    use HasRefreshTokenManager;
    use HasAccessTokenManager;

    /**
     * @return string[]
     */
    protected function getRevocationMethods()
    {
        $managers = [
            'access_token' => 'tryRevokeAccessToken',
        ];
        if (!is_null($this->getRefreshTokenManager())) {
            $managers['refresh_token'] = 'tryRevokeRefreshToken';
        }

        return $managers;
    }

    /**
     * {@inheritdoc}
     */
    public function revoke(Request $request)
    {
        $this->getParameters($request, $token, $token_type_hint, $callback);
        if (!$request->isSecure()) {
            $exception = $this->getExceptionManager()->getException(ExceptionManagerInterface::BAD_REQUEST, ExceptionManagerInterface::INVALID_REQUEST, 'Request must be secured');

            return $this->getResponseContent($exception->getHttpResponse()->getContent(), $callback, $exception->getHttpCode());
        }
        if (is_null($token)) {
            $exception = $this->getExceptionManager()->getException(ExceptionManagerInterface::BAD_REQUEST, ExceptionManagerInterface::INVALID_REQUEST, 'Parameter "token" is missing');

            return $this->getResponseContent($exception->getHttpResponse()->getContent(), $callback, $exception->getHttpCode());
        }
        $found = null;
        try {
            $client = $this->getClientManagerSupervisor()->findClient($request, $found);
        } catch (BaseException $e) {
            if (!is_null($found)) {
                return $this->getResponseContent($e->getHttpResponse()->getContent(), $callback, $e->getHttpCode());
            }
            $client = null;
        }

        return $this->revokeToken($token, $token_type_hint, $client, $callback);
    }

    /**
     * @param string      $content
     * @param string|null $callback
     * @param int         $code
     *
     * @return \Symfony\Component\HttpFoundation\Response
     */
    private function getResponseContent($content, $callback, $code = 200)
    {
        return new Response(is_null($callback) ? '' : $callback.'('.$content.')', $code);
    }

    /**
     * @param \Symfony\Component\HttpFoundation\Request $request
     * @param string                                    $token
     * @param string|null                               $token_type_hint
     * @param string|null                               $callback
     *
     * @throws \OAuth2\Exception\BaseExceptionInterface
     */
    private function getParameters(Request $request, &$token, &$token_type_hint, &$callback)
    {
        foreach (['token', 'token_type_hint', 'callback'] as $key) {
            $$key = $request->query->has($key) ? $request->query->get($key) : RequestBody::getParameter($request, $key);
        }
    }

    /**
     * @param string|null                         $token
     * @param string|null                         $token_type_hint
     * @param \OAuth2\Client\ClientInterface|null $client
     * @param string|null                         $callback
     *
     * @return \Symfony\Component\HttpFoundation\Response
     * @throws \OAuth2\Exception\BaseExceptionInterface
     */
    private function revokeToken($token = null, $token_type_hint = null, ClientInterface $client = null, $callback = null)
    {
        $methods = $this->getRevocationMethods();
        if (is_null($token_type_hint)) {
            foreach ($methods as $method) {
                $this->$method($token, $client);
            }
        } elseif (array_key_exists($token_type_hint, $methods)) {
            $method = $methods[$token_type_hint];
            $this->$method($token, $client);
        } else {
            $exception = $this->getExceptionManager()->getException(ExceptionManagerInterface::NOT_IMPLEMENTED, 'unsupported_token_type', sprintf('Token type "%s" not supported', $token_type_hint));
            return $this->getResponseContent($exception->getHttpResponse()->getContent(), $callback, $exception->getHttpCode());
        }
        return $this->getResponseContent('', $callback);
    }

    /**
     * @param string|null                    $token
     * @param \OAuth2\Client\ClientInterface $client
     */
    private function tryRevokeAccessToken($token = null, ClientInterface $client = null)
    {
        $access_token = $this->getAccessTokenManager()->getAccessToken($token);
        if (!is_null($access_token) && true === $this->isClientVerified($access_token, $client)) {
            if (true === $this->getConfiguration()->get('revoke_refresh_token_and_access_token', true) && !is_null($access_token->getRefreshToken())) {
                $this->tryRevokeRefreshToken($access_token->getRefreshToken(), $client);
            }
            $this->getAccessTokenManager()->revokeAccessToken($access_token);
        }
    }

    /**
     * @param string|null                    $token
     * @param \OAuth2\Client\ClientInterface $client
     *
     * @throws \OAuth2\Exception\BaseExceptionInterface
     */
    private function tryRevokeRefreshToken($token = null, ClientInterface $client = null)
    {
        $refresh_token = $this->getRefreshTokenManager()->getRefreshToken($token);
        if (!is_null($refresh_token) && true === $this->isClientVerified($refresh_token, $client)) {
            $this->getRefreshTokenManager()->revokeRefreshToken($refresh_token);
        }
    }

    /**
     * @param \OAuth2\Token\AccessTokenInterface|\OAuth2\Token\RefreshTokenInterface $token
     * @param \OAuth2\Client\ClientInterface|null                                    $client
     *
     * @return bool
     */
    private function isClientVerified($token, ClientInterface $client = null)
    {
        if (!is_null($client)) {
            // The client ID of the token is the same as client authenticated
            return $token->getClientPublicId() === $client->getPublicId();
        } else {
            // We try to get the client
            $client = $this->getClientManagerSupervisor()->getClient($token->getClientPublicId());

            // Return false if the client is a confidential client (confidential client must be authenticated)
            return !$client instanceof ConfidentialClientInterface;
        }
    }
}
