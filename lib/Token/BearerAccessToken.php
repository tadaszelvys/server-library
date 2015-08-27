<?php

namespace OAuth2\Token;

use OAuth2\Behaviour\HasExceptionManager;
use OAuth2\Exception\ExceptionManagerInterface;
use Symfony\Component\HttpFoundation\Request;
use Util\RequestBody;

class BearerAccessToken implements AccessTokenTypeInterface
{
    use HasExceptionManager;

    /**
     * Get the list of methods to find the access token
     * This method can be override to add new way to find an access token.
     * These methods are those official supported by the RFC6750.
     *
     * @return string[]
     */
    protected function getTokenFromMethods()
    {
        return [
            'getTokenFromHeaders',
            'getTokenFromRequestBody',
            'getTokenFromQuery',
        ];
    }

    /**
     * Get the token from the authorization header.
     *
     * @param Request $request
     *
     * @return string|null
     */
    protected function getTokenFromHeaders(Request $request)
    {
        $header = $request->headers->get('AUTHORIZATION');

        if (is_null($header)) {
            return;
        }

        if (!preg_match('/'.preg_quote('Bearer', '/').'\s([a-zA-Z0-9\-_\+~\/\.]+)/', $header, $matches)) {
            return;
        }

        $token = $matches[1];

        return $token;
    }

    /**
     * Get the token from the request body.
     *
     * @param Request $request
     *
     * @return string|null
     */
    protected function getTokenFromRequestBody(Request $request)
    {
        return RequestBody::getParameter($request, 'access_token');
    }

    /**
     * Get the token from the query string.
     *
     * @param Request $request
     *
     * @return string|null
     */
    protected function getTokenFromQuery(Request $request)
    {
        if (!$token = $request->query->get('access_token')) {
            return;
        }

        return $token;
    }

    /**
     * {@inheritdoc}
     */
    public function prepareAccessToken(AccessTokenInterface $token)
    {
        $data = $token->jsonSerialize();

        return array_merge($data, [
            'token_type' => 'Bearer',
        ]);
    }

    /**
     * {@inheritdoc}
     */
    public function findAccessToken(Request $request)
    {
        $tokens = [];
        $methods = $this->getTokenFromMethods();

        foreach ($methods as $method) {
            $token = $this->$method($request);

            if (!is_null($token)) {
                $tokens[] = $token;
            }
        }

        if (count($tokens) > 1) {
            throw $this->getExceptionManager()->getException(ExceptionManagerInterface::BAD_REQUEST, ExceptionManagerInterface::INVALID_REQUEST, 'Only one method may be used to authenticate at a time.');
        } elseif (empty($tokens)) {
            return;
        }

        $accessToken = current($tokens);
        if (!is_string($accessToken)) {
            throw $this->getExceptionManager()->getException(ExceptionManagerInterface::INTERNAL_SERVER_ERROR, 'invalid_result', 'A method returned an invalid data type.');
        }

        return $accessToken;
    }

    /**
     * This token type does not require extra-check.
     *
     * {@inheritdoc}
     */
    public function isAccessTokenValid(Request $request, AccessTokenInterface $token)
    {
        return true;
    }
}
