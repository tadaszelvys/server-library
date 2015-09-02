<?php

namespace OAuth2\Client;

use OAuth2\Behaviour\HasExceptionManager;
use OAuth2\Exception\ExceptionManagerInterface;
use Psr\Http\Message\ServerRequestInterface;

abstract class PublicClientManager implements ClientManagerInterface
{
    use HasExceptionManager;

    /**
     * @return array
     */
    abstract protected function findClientMethods();

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

        if (!$client instanceof PublicClientInterface) {
            throw $this->getExceptionManager()->getException(ExceptionManagerInterface::INTERNAL_SERVER_ERROR, ExceptionManagerInterface::INVALID_CLIENT, 'The client is not an instance of PublicClientInterface.');
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
}
