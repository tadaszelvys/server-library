<?php

namespace OAuth2\Client;

use Jose\JWEInterface;
use Jose\JWSInterface;
use Jose\JWTInterface;
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
     * By default, this method does nothing, but should be overridden and check other claims (issuer, jti...)
     *
     * @param \Jose\JWTInterface $jwt
     *
     * @throws \OAuth2\Exception\BaseExceptionInterface
     */
    protected function checkJWT(JWTInterface $jwt)
    {
    }

    /**
     * @return string[]
     */
    protected function getRequiredClaims()
    {
        return [
            'iss',
            'aud',
            'sub',
            'exp',
        ];
    }

    /**
     * @param \OAuth2\Client\JWTClientInterface     $client
     * @param \Jose\JWEInterface|\Jose\JWSInterface $jwt
     *
     * @return bool
     * @throws \OAuth2\Exception\BaseExceptionInterface
     */
    protected function isClientAssertionValid(JWTClientInterface $client, $jwt)
    {
        //If the assertion is a JWE, we decrypt
        if ($jwt instanceof JWEInterface && false === $this->loadJWE($client, $jwt)) {
            return false;
        }
        //If the assertion (or the payload of the JWE) is not a JWS, this is not valid
        if (!in_array($jwt->getAlgorithm(), $client->getAllowedSignatureAlgorithms())) {
            return false;
        }

        $this->checkAssertion($jwt);

        $is_signature_verified = $this->getJWTLoader()->verifySignature($jwt, $client->getPublicKeySet());

        return $is_signature_verified;
    }

    /**
     * @param \OAuth2\Client\JWTClientInterface $client
     * @param \Jose\JWEInterface                 $jwt
     *
     * @return bool
     * @throws \OAuth2\Exception\BaseExceptionInterface
     */
    protected function loadJWE(JWTClientInterface $client, JWEInterface &$jwt)
    {
        if (!in_array($jwt->getEncryptionAlgorithm(), $this->getAllowedEncryptionAlgorithms()) || !in_array($jwt->getAlgorithm(), $this->getAllowedEncryptionAlgorithms())) {
            return false;
        }
        try {
            if (false === $this->getJWTLoader()->decrypt($jwt, $this->getPrivateKeySet())) {
                return false;
            }
            $jwt = $this->getJWTLoader()->load($jwt->getPayload());
        } catch (\Exception $e) {
            throw $this->getExceptionManager()->getException(ExceptionManagerInterface::BAD_REQUEST, ExceptionManagerInterface::INVALID_REQUEST, $e->getMessage());
        }
        if (!$jwt instanceof JWSInterface) {
            throw $this->getExceptionManager()->getException(ExceptionManagerInterface::BAD_REQUEST, ExceptionManagerInterface::INVALID_REQUEST, 'Encrypted token does not contain signed token.');
        }
        if ($client->getPublicId() !== $jwt->getSubject()) {
            return false;
        }
        return true;
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
            throw $this->getExceptionManager()->getException(ExceptionManagerInterface::INTERNAL_SERVER_ERROR, ExceptionManagerInterface::INVALID_REQUEST, 'The client is not an instance of JWTClientInterface.');
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

        $this->checkAssertion($jwt);

        return $jwt;
    }

    /**
     * @param \Jose\JWTInterface $jwt
     *
     * @throws \OAuth2\Exception\BaseExceptionInterface
     */
    private function checkAssertion(JWTInterface $jwt)
    {
        foreach ($this->getRequiredClaims() as $claim) {
            if (is_null($jwt->getHeaderOrPayloadValue($claim))) {
                throw $this->getExceptionManager()->getException(ExceptionManagerInterface::BAD_REQUEST, ExceptionManagerInterface::INVALID_REQUEST, sprintf('Claim "%s" is mandatory.', $claim));
            }
        }
        try {
            $this->getJWTLoader()->verify($jwt);
        } catch(\Exception $e) {
            throw $this->getExceptionManager()->getException(ExceptionManagerInterface::BAD_REQUEST, ExceptionManagerInterface::INVALID_REQUEST, $e->getMessage());
        }

        $this->checkJWT($jwt);
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
