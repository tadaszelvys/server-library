<?php

namespace OAuth2\Client;

use Jose\JWEInterface;
use Jose\JWSInterface;
use OAuth2\Behaviour\HasConfiguration;
use OAuth2\Behaviour\HasExceptionManager;
use OAuth2\Exception\ExceptionManagerInterface;
use Symfony\Component\HttpFoundation\Request;
use Util\RequestBody;

abstract class JWTClientManager implements ClientManagerInterface
{
    use HasExceptionManager;
    use HasConfiguration;

    /**
     * @return \Jose\LoaderInterface
     */
    abstract protected function getJWTLoader();

    /**
     * @return \Jose\JWKSetInterface
     */
    abstract protected function getPrivateKeySet();

    /**
     * @return string[]
     */
    abstract protected function getAllowedEncryptionAlgorithms();

    /**
     * @param \OAuth2\Client\JWTClientInterface     $client
     * @param \Jose\JWEInterface|\Jose\JWSInterface $jwt
     *
     * @return bool
     */
    protected function isClientAssertionValid(JWTClientInterface $client, $jwt)
    {
        //If the assertion is a JWE, we decrypt
        if ($jwt instanceof JWEInterface) {
            if (!in_array($jwt->getEncryptionAlgorithm(), $this->getAllowedEncryptionAlgorithms()) || !in_array($jwt->getAlgorithm(), $this->getAllowedEncryptionAlgorithms())) {
                return false;
            }
            if (false === $this->getJWTLoader()->decrypt($jwt, $this->getPrivateKeySet())) {
                return false;
            }
            $jwt = $jwt->getPayload();
        }
        //If the assertion (or the payload of the JWE) is not a JWS, this is not valid
        if (!$jwt instanceof JWSInterface) {
            return false;
        }
        if (!in_array($jwt->getAlgorithm(), $client->getAllowedSignatureAlgorithms())) {
            return false;
        }

        //Then we verify the algorithm used, the claims (expiration, audience...) and the signature and we return the result
        return $this->getJWTLoader()->verify($jwt) && $this->getJWTLoader()->verifySignature($jwt, $client->getPublicKeySet());
    }

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
    public function findClient(Request $request, &$client_public_id_found = null)
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
            throw $this->getExceptionManager()->getException('InternalServerError', 'invalid_client', 'The client is not an instance of JWTClientInterface.');
        }

        if (!$this->isClientAssertionValid($client, $assertions[0])) {
            $client_public_id_found = $client->getPublicId();
            return;
        }

        return $client;
    }

    /**
     * @param \Symfony\Component\HttpFoundation\Request $request
     * @param string|null                               $client_public_id_found
     *
     * @return \Jose\JWEInterface|\Jose\JWSInterface
     */
    protected function findCredentialsFromClientAssertion(Request $request, &$client_public_id_found = null)
    {
        $client_assertion_type = RequestBody::getParameter($request, 'client_assertion_type');

        //We verify the client assertion type in the request
        if ('urn:ietf:params:oauth:client-assertion-type:jwt-bearer' !== $client_assertion_type) {
            return;
        }

        $client_assertion = RequestBody::getParameter($request, 'client_assertion');
        //We verify the client assertion exists
        if (is_null($client_assertion)) {
            return;
        }

        //We load the client assertion
        $jwt = $this->getJWTLoader()->load($client_assertion);

        if (!$jwt instanceof JWEInterface && !$jwt instanceof JWSInterface) {
            return;
        }

        if (is_null($jwt->getExpirationTime()) || !$this->getJWTLoader()->verify($jwt)) {
            return;
        }

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

        return $this->getClient($result[0]->getIssuer());
    }
}
