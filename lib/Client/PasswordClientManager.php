<?php

namespace OAuth2\Client;

use OAuth2\Behaviour\HasConfiguration;
use OAuth2\Behaviour\HasExceptionManager;
use OAuth2\Exception\ExceptionManagerInterface;
use OAuth2\Util\RequestBody;
use Psr\Http\Message\ServerRequestInterface;

abstract class PasswordClientManager implements ClientManagerInterface
{
    use HasExceptionManager;
    use HasConfiguration;

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
     * @return self
     */
    protected function updateClientCredentials(PasswordClientInterface $client)
    {
        if (!is_null($client->getPlaintextSecret())) {
            $secret = hash($this->getHashAlgorithm(), $client->getSalt().$client->getPlaintextSecret());
            $client->setSecret($secret);
            $client->clearCredentials();
        }

        return $this;
    }

    /**
     * @param \OAuth2\Client\PasswordClientInterface $client
     * @param string                                 $secret
     *
     * @return bool
     */
    protected function checkClientCredentials(PasswordClientInterface $client, $secret)
    {
        return hash($this->getHashAlgorithm(), $client->getSalt().$secret) === $client->getSecret();
    }

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
    public function findClient(ServerRequestInterface $request, &$client_public_id_found = null)
    {
        $methods = $this->findClientCredentialsMethods();
        $credentials = [];

        foreach ($methods as $method) {
            $data = $this->$method($request, $client_public_id_found);
            if (!is_null($data)) {
                $credentials[] = $data;
            }
        }

        $client = $this->checkResult($credentials);
        if (is_null($client)) {
            return $client;
        }

        if (!$client instanceof PasswordClientInterface) {
            throw $this->getExceptionManager()->getException('InternalServerError', 'invalid_client', 'The client is not an instance of PasswordClientInterface.');
        }

        if (!$this->checkClientCredentials($client, $credentials[0]['client_secret'])) {
            $client_public_id_found = $client->getPublicId();

            return;
        }

        return $client;
    }

    /**
     * @param \Psr\Http\Message\ServerRequestInterface $request
     *
     * @return string[]
     */
    protected function findCredentialsFromAuthenticationScheme(ServerRequestInterface $request, &$client_public_id_found = null)
    {
        $server_params = $request->getServerParams();
        if (array_key_exists('PHP_AUTH_USER', $server_params) && array_key_exists('PHP_AUTH_PW', $server_params)) {
            return [
                'client_id'     => $server_params['PHP_AUTH_USER'],
                'client_secret' => $server_params['PHP_AUTH_PW'],
            ];
        }
        if (!is_null($authenticate = $request->getAttribute('Authorization')) && strtolower(substr($authenticate, 0, 6)) === 'basic ') {
            list($client_id, $client_secret) = explode(':', base64_decode(substr($authenticate, 6, strlen($authenticate) - 6)));
            if (!empty($client_id) && !empty($client_secret)) {
                return [
                    'client_id'     => $client_id,
                    'client_secret' => $client_secret,
                ];
            }
        }
    }

    /**
     * @param \Psr\Http\Message\ServerRequestInterface $request
     *
     * @return string[]|null
     */
    protected function findCredentialsFromRequestBody(ServerRequestInterface $request, &$client_public_id_found = null)
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
    }

    /**
     * @param array $result
     *
     * @throws \OAuth2\Exception\BaseExceptionInterface
     *
     * @return null|\OAuth2\Client\ClientInterface
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
