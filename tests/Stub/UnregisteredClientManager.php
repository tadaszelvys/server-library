<?php

namespace OAuth2\Test\Stub;

use OAuth2\Behaviour\HasExceptionManager;
use OAuth2\Client\ClientManagerInterface;
use OAuth2\Client\UnregisteredClient;
use OAuth2\Exception\ExceptionManagerInterface;
use Psr\Http\Message\ServerRequestInterface;

class UnregisteredClientManager implements ClientManagerInterface
{
    use HasExceptionManager;

    /**
     * {@inheritdoc}
     */
    public function findClient(ServerRequestInterface $request, &$client_public_id_found = null)
    {
        $methods = $this->findClientMethods();
        $result = [];

        foreach ($methods as $method) {
            $data = $this->$method($request, $client_public_id_found);
            if (!is_null($data)) {
                $result[] = $data;
            }
        }

        $client = $this->checkResult($result);
        if (is_null($client)) {
            return $client;
        }

        if (!$client instanceof UnregisteredClient) {
            throw $this->getExceptionManager()->getException(ExceptionManagerInterface::INTERNAL_SERVER_ERROR, ExceptionManagerInterface::INVALID_CLIENT, 'The client is not an instance of UnregisteredClient.');
        }

        return $client;
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

        return $this->getClient($result[0]);
    }

    /**
     * {@inheritdoc}
     */
    public function getClient($client_id)
    {
        /*
         * The following verification is very important!
         * If not defined, this method will always return a client, even if the client ID
         * is already used by a confidential client for example.
         */
        if ('**UNREGISTERED**--' !== substr($client_id, 0, 18)) {
            return;
        }

        $client = new UnregisteredClient();
        $client
            ->setAllowedGrantTypes(['code', 'authorization_code'])
            ->setPublicId($client_id);

        return $client;
    }

    /**
     * {@inheritdoc}
     */
    protected function findClientMethods()
    {
        return [
            'findClientUsingHeader',
        ];
    }

    /**
     * @param \Psr\Http\Message\ServerRequestInterface $request
     * @param string|null                              $client_public_id_found
     *
     * @return string|null
     */
    protected function findClientUsingHeader(ServerRequestInterface $request, &$client_public_id_found = null)
    {
        $header = $request->getHeader('X-OAuth2-Unregistered-Client-ID');

        if (empty($header)) {
            return;
        } elseif (is_array($header)) {
            $client_public_id_found = $header[0];

            return $header[0];
        } else {
            $client_public_id_found = $header;

            return $header;
        }
    }
}
