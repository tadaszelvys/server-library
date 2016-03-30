<?php

/*
 * The MIT License (MIT)
 *
 * Copyright (c) 2014-2016 Spomky-Labs
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file for details.
 */

namespace OAuth2\Client;

use Assert\Assertion;
use Jose\Object\JWSInterface;
use OAuth2\Behaviour\HasExceptionManager;
use OAuth2\Behaviour\HasJWTLoader;
use OAuth2\Exception\ExceptionManagerInterface;
use OAuth2\Util\JWTLoader;
use OAuth2\Util\RequestBody;
use Psr\Http\Message\ServerRequestInterface;

abstract class PasswordClientManager implements ClientManagerInterface
{
    use HasJWTLoader;
    use HasExceptionManager;
    use ClientAssertionTrait;

    /**
     * @var string
     */
    private $realm;

    /**
     * @var bool
     */
    private $password_client_credentials_in_body_request_allowed = false;

    /**
     * PasswordClientManager constructor.
     *
     * @param \OAuth2\Util\JWTLoader                      $jwt_loader
     * @param \OAuth2\Exception\ExceptionManagerInterface $exception_manager
     * @param string                                      $realm
     */
    public function __construct(JWTLoader $jwt_loader, ExceptionManagerInterface $exception_manager, $realm)
    {
        Assertion::string($realm);

        $this->setJWTLoader($jwt_loader);
        $this->setExceptionManager($exception_manager);
        $this->realm = $realm;
    }

    /**
     * {@inheritdoc}
     */
    public function getSchemesParameters()
    {
        return [
            sprintf('Basic realm="%s",charset=UTF-8', $this->getRealm()),
        ];
    }

    /**
     * {@inheritdoc}
     */
    public function findClient(ServerRequestInterface $request, &$client_credentials = null)
    {
        $methods = $this->getClientCredentialsMethods();
        $credentials = [];

        foreach ($methods as $method) {
            $data = $this->$method($request);
            if (null !== ($data)) {
                $credentials[] = $data;
            }
        }

        $client = $this->checkResult($credentials);
        if ($client instanceof PasswordClientInterface) {
            $client_credentials = $credentials[0]['client_credentials'];
        }

        return $client;
    }

    /**
     * {@inheritdoc}
     */
    public function isClientAuthenticated(ClientInterface $client, $client_credentials, ServerRequestInterface $request, &$reason = null)
    {
        if (true === $client->areCredentialsExpired()) {
            $reason = 'Credentials expired.';

            return false;
        }

        if ($client_credentials instanceof JWSInterface) {
            return $this->verifyClientAssertion($client, $client_credentials, $reason);
        }

        if (false === hash_equals($client->getSecret(), $client_credentials)) {
            $reason = 'Bad credentials.';

            return false;
        }

        return true;
    }

    /**
     * @return bool
     */
    public function arePasswordClientCredentialsInBodyRequestAllowed()
    {
        return $this->password_client_credentials_in_body_request_allowed;
    }

    public function enablePasswordClientCredentialsInBodyRequest()
    {
        $this->password_client_credentials_in_body_request_allowed = true;
    }

    public function disablePasswordClientCredentialsInBodyRequest()
    {
        $this->password_client_credentials_in_body_request_allowed = false;
    }

    /**
     * {@inheritdoc}
     */
    public function isClientSupported(ClientInterface $client)
    {
        return $client instanceof PasswordClientInterface;
    }

    /**
     * {@inheritdoc}
     */
    public function getSupportedAuthenticationMethods()
    {
        return array_keys($this->getClientCredentialsMethods());
    }

    /**
     * @return string[]
     */
    protected function getClientCredentialsMethods()
    {
        $methods = [
            'client_secret_basic' => 'findCredentialsFromBasicAuthenticationScheme',
            'client_secret_jwt'   => 'findCredentialsFromClientAssertion',
        ];

        // This authentication method is not recommended by the RFC6749.
        // This option allows to enable this authentication method (not recommended).
        // See http://tools.ietf.org/html/rfc6749#section-2.3.1
        if ($this->arePasswordClientCredentialsInBodyRequestAllowed()) {
            $methods['client_secret_post'] = 'findCredentialsFromRequestBody';
        }

        return $methods;
    }

    /**
     * @param \Psr\Http\Message\ServerRequestInterface $request
     *
     * @return string[]
     */
    protected function findCredentialsFromBasicAuthenticationScheme(ServerRequestInterface $request)
    {
        $server_params = $request->getServerParams();
        if (array_key_exists('PHP_AUTH_USER', $server_params) && array_key_exists('PHP_AUTH_PW', $server_params)) {
            return [
                'client_id'          => $server_params['PHP_AUTH_USER'],
                'client_credentials' => $server_params['PHP_AUTH_PW'],
            ];
        }
        $header = $request->getHeader('Authorization');
        if (0 < count($header) && mb_strtolower(mb_substr($header[0], 0, 6, '8bit'), '8bit') === 'basic ') {
            list($client_id, $client_secret) = explode(':', base64_decode(mb_substr($header[0], 6, mb_strlen($header[0], '8bit') - 6, '8bit')));
            if (!empty($client_id) && !empty($client_secret)) {
                return [
                    'client_id'          => $client_id,
                    'client_credentials' => $client_secret,
                ];
            }
        }
    }

    /**
     * @param \Psr\Http\Message\ServerRequestInterface $request
     *
     * @return string[]|null
     */
    protected function findCredentialsFromRequestBody(ServerRequestInterface $request)
    {
        $client_id = RequestBody::getParameter($request, 'client_id');
        $client_secret = RequestBody::getParameter($request, 'client_secret');

        if (null !== ($client_id) && null !== ($client_secret)) {
            return [
                'client_id'          => $client_id,
                'client_credentials' => $client_secret,
            ];
        }
    }

    /**
     * @param array $result
     *
     * @throws \OAuth2\Exception\BaseExceptionInterface
     *
     * @return null|\OAuth2\Client\PasswordClientInterface
     */
    private function checkResult(array $result)
    {
        if (count($result) > 1) {
            throw $this->getExceptionManager()->getBadRequestException(ExceptionManagerInterface::INVALID_REQUEST, 'Only one authentication method may be used to authenticate the client.');
        }

        if (count($result) < 1) {
            return;
        }

        return $this->getClient($result[0]['client_id']);
    }

    /**
     * @return string
     */
    private function getRealm()
    {
        return $this->realm;
    }
}
