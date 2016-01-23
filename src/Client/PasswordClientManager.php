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

use OAuth2\Behaviour\HasConfiguration;
use OAuth2\Behaviour\HasExceptionManager;
use OAuth2\Configuration\ConfigurationInterface;
use OAuth2\Exception\ExceptionManagerInterface;
use OAuth2\Util\RequestBody;
use Psr\Http\Message\ServerRequestInterface;

abstract class PasswordClientManager implements ClientManagerInterface
{
    use HasExceptionManager;
    use HasConfiguration;

    /**
     * PasswordClientManager constructor.
     *
     * @param \OAuth2\Exception\ExceptionManagerInterface  $exception_manager
     * @param \OAuth2\Configuration\ConfigurationInterface $configuration
     *
     * @throws \OAuth2\Exception\BaseExceptionInterface
     */
    public function __construct(ExceptionManagerInterface $exception_manager, ConfigurationInterface $configuration)
    {
        $this->setExceptionManager($exception_manager);
        $this->setConfiguration($configuration);
    }

    /**
     * {@inheritdoc}
     */
    public function getSchemesParameters()
    {
        return [
            sprintf('Basic realm="%s",charset=UTF-8', $this->getConfiguration()->get('realm', 'Service'))
        ];
    }

    /**
     * {@inheritdoc}
     */
    public function findClient(ServerRequestInterface $request, &$client_credentials = null)
    {
        $methods = $this->findClientCredentialsMethods();
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
        if (!$client instanceof PasswordClientInterface) {
            return false;
        }

        return hash($this->getHashAlgorithm(), $client->getSalt().$client_credentials) === $client->getSecret();
    }

    /**
     * @return string
     */
    protected function getHashAlgorithm()
    {
        return 'sha512';
    }

    /**
     * @param \OAuth2\Client\PasswordClientInterface $client
     *
     * @throws \OAuth2\Exception\BaseExceptionInterface
     */
    protected function updateClientCredentials(PasswordClientInterface $client)
    {
        if (null !== ($client->getPlaintextSecret())) {
            $secret = hash($this->getHashAlgorithm(), $client->getSalt().$client->getPlaintextSecret());
            $client->setSecret($secret);

            $client->clearCredentials();
        }
    }

    /**
     * @return string[]
     */
    protected function findClientCredentialsMethods()
    {
        $methods = [
            'findCredentialsFromBasicAuthenticationScheme',
        ];

        // This authentication method is not recommended by the RFC6749. This option allows to disable this authentication method.
        // See http://tools.ietf.org/html/rfc6749#section-2.3.1
        if ($this->getConfiguration()->get('allow_password_client_credentials_in_body_request', true)) {
            $methods[] = 'findCredentialsFromRequestBody';
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
        if (0 < count($header) && strtolower(substr($header[0], 0, 6)) === 'basic ') {
            list($client_id, $client_secret) = explode(':', base64_decode(substr($header[0], 6, strlen($header[0]) - 6)));
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
            throw $this->getExceptionManager()->getException(ExceptionManagerInterface::BAD_REQUEST, ExceptionManagerInterface::INVALID_REQUEST, 'Only one authentication method may be used to authenticate the client.');
        }

        if (count($result) < 1) {
            return;
        }

        return $this->getClient($result[0]['client_id']);
    }
}
