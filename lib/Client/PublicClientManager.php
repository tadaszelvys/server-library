<?php

namespace OAuth2\Client;

use OAuth2\Behaviour\HasExceptionManager;
use Symfony\Component\HttpFoundation\Request;
use OAuth2\Exception\ExceptionManagerInterface;

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
    public function findClient(Request $request)
    {
        $methods = $this->findClientMethods();
        $result = array();

        foreach ($methods as $method) {
            $data = $this->$method($request);
            if (null !== $data) {
                $result[] = $data;
            }
        }

        $client = $this->checkResult($result);
        if (is_null($client) || is_string($client)) {
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
     * @return null|\OAuth2\Client\ClientInterface|string
     *
     * @throws \OAuth2\Exception\BaseExceptionInterface
     */
    private function checkResult(array $result)
    {
        if (count($result) > 1) {
            throw $this->getExceptionManager()->getException(ExceptionManagerInterface::BAD_REQUEST, ExceptionManagerInterface::INVALID_REQUEST, 'Only one authentication method may be used to authenticate the client.');
        }

        if (count($result) < 1) {
            return;
        }

        $client = $this->getClient($result[0]);

        return is_null($client) ? $result[0] : $client;
    }
}
