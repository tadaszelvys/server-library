<?php

namespace OAuth2\Client;

use Jose\JWEInterface;
use Jose\JWKSetManagerInterface;
use Jose\JWSInterface;
use Jose\JWTInterface;
use Jose\LoaderInterface;
use OAuth2\Behaviour\CanLoadJWT;
use OAuth2\Behaviour\HasConfiguration;
use OAuth2\Behaviour\HasExceptionManager;
use OAuth2\Exception\ExceptionManagerInterface;
use OAuth2\Util\RequestBody;
use Psr\Http\Message\ServerRequestInterface;

abstract class JWTClientManager implements ClientManagerInterface
{
    use HasExceptionManager;
    use HasConfiguration;
    use CanLoadJWT;

    /**
     * @return string[]
     */
    protected function findClientCredentialsMethods()
    {
        $methods = [
            'findCredentialsFromClientAssertion',
        ];

        return $methods;
    }

    /**
     * {@inheritdoc}
     */
    public function findClient(ServerRequestInterface $request, &$client_public_id_found = null)
    {
        $methods = $this->findClientCredentialsMethods();
        $assertions = [];

        foreach ($methods as $method) {
            $data = $this->$method($request, $client_public_id_found);
            if (!is_null($data)) {
                $assertions[] = $data;
            }
        }

        $client = $this->checkResult($assertions);
        if (is_null($client)) {
            return $client;
        }

        if (!$client instanceof JWTClientInterface) {
            throw $this->getExceptionManager()->getException(ExceptionManagerInterface::INTERNAL_SERVER_ERROR, ExceptionManagerInterface::INVALID_REQUEST, 'The client is not an instance of JWTClientInterface.');
        }

        $this->verifySignature($assertions[0], $client);

        return $client;
    }

    /**
     * @param \Psr\Http\Message\ServerRequestInterface $request
     * @param string|null                              $client_public_id_found
     *
     * @throws \OAuth2\Exception\BaseExceptionInterface
     *
     * @return \Jose\JWSInterface
     */
    protected function findCredentialsFromClientAssertion(ServerRequestInterface $request, &$client_public_id_found = null)
    {
        $client_assertion_type = RequestBody::getParameter($request, 'client_assertion_type');

        //We verify the client assertion type in the request
        if ('urn:ietf:params:oauth:client-assertion-type:jwt-bearer' !== $client_assertion_type) {
            return;
        }

        $client_assertion = RequestBody::getParameter($request, 'client_assertion');
        //We verify the client assertion exists
        if (is_null($client_assertion)) {
            throw $this->getExceptionManager()->getException(ExceptionManagerInterface::BAD_REQUEST, ExceptionManagerInterface::INVALID_REQUEST, 'Parameter "client_assertion" is missing.');
        }

        //We load the assertion
        $jwt = $this->loadAssertion($client_assertion);
        if ($jwt instanceof JWEInterface) {
            $this->verifyAssertion($jwt);
            $jwt = $this->decryptAssertion($jwt);
        }
        $this->verifyAssertion($jwt);

        return $jwt;
    }

    /**
     * @param \Jose\JWEInterface[] $result
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

        return $this->getClient($result[0]->getSubject());
    }
}
