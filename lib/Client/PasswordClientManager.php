<?php

namespace OAuth2\Client;

use OAuth2\Behaviour\HasConfiguration;
use OAuth2\Behaviour\HasExceptionManager;
use OAuth2\Exception\ExceptionManagerInterface;
use Symfony\Component\HttpFoundation\Request;
use Util\RequestBody;

abstract class PasswordClientManager implements ClientManagerInterface
{
    use HasExceptionManager;
    use HasConfiguration;

    /**
     * @param \OAuth2\Client\PasswordClientInterface $client
     * @param string                                 $secret
     *
     * @return bool
     */
    abstract protected function checkClientCredentials(PasswordClientInterface $client, $secret);

    /**
     * @return string[]
     */
    protected function findClientCredentialsMethods()
    {
        $methods = [
            'findCredentialsFromAuthenticationScheme',
        ];

        // This authentication method is not recommended by the RFC6749. This option allows to disable this authentication method.
        // See http://tools.ietf.org/html/rfc6749#section-2.3.1
        if ($this->getConfiguration()->get('allow_password_client_credentials_in_body_request', true)) {
            $methods[] = 'findCredentialsFromRequestBody';
        }

        return $methods;
    }

    /**
     * {@inheritdoc}
     */
    public function findClient(Request $request)
    {
        $methods = $this->findClientCredentialsMethods();
        $credentials = [];

        foreach ($methods as $method) {
            $data = $this->$method($request);
            if (!is_null($data)) {
                $credentials[] = $data;
            }
        }

        $client = $this->checkResult($credentials);
        if (is_null($client) || is_string($client)) {
            return $client;
        }

        if (!$client instanceof PasswordClientInterface) {
            throw $this->getExceptionManager()->getException('InternalServerError', 'invalid_client', 'The client is not an instance of PasswordClientInterface.');
        }

        if (!$this->checkClientCredentials($client, $credentials[0]['client_secret'])) {
            return $client->getPublicId();
        }

        return $client;
    }

    /**
     * @param \Symfony\Component\HttpFoundation\Request $request
     *
     * @return string[]
     */
    protected function findCredentialsFromAuthenticationScheme(Request $request)
    {
        if ($request->server->get('PHP_AUTH_USER') && $request->server->get('PHP_AUTH_PW')) {
            return [
                'client_id'     => $request->server->get('PHP_AUTH_USER'),
                'client_secret' => $request->server->get('PHP_AUTH_PW'),
            ];
        }
        if (!is_null($authenticate = $request->headers->get('Authorization')) && strtolower(substr($authenticate, 0, 6)) === 'basic ') {
            list($client_id, $client_secret) = explode(':', base64_decode(substr($authenticate, 6, strlen($authenticate) - 6)));
            if (!empty($client_id) && !empty($client_secret)) {
                return [
                    'client_id'     => $client_id,
                    'client_secret' => $client_secret,
                ];
            }
        }

        return;
    }

    /**
     * @param \Symfony\Component\HttpFoundation\Request $request
     *
     * @return string[]|null
     */
    protected function findCredentialsFromRequestBody(Request $request)
    {
        $parameters = RequestBody::getParameters($request);
        if (is_null($parameters)) {
            return;
        }
        if (array_key_exists('client_id', $parameters) && array_key_exists('client_secret', $parameters)) {
            return [
                'client_id'     => $parameters['client_id'],
                'client_secret' => $parameters['client_secret'],
            ];
        }

        return;
    }

    /**
     * @param array $result
     *
     * @throws \OAuth2\Exception\BaseExceptionInterface
     *
     * @return null|\OAuth2\Client\ClientInterface|string
     */
    private function checkResult(array $result)
    {
        if (count($result) > 1) {
            throw $this->getExceptionManager()->getException(ExceptionManagerInterface::BAD_REQUEST, ExceptionManagerInterface::INVALID_REQUEST, 'Only one authentication method may be used to authenticate the client.');
        }

        if (count($result) < 1) {
            return;
        }

        $client = $this->getClient($result[0]['client_id']);

        return is_null($client) ? $result[0]['client_id'] : $client;
    }
}
