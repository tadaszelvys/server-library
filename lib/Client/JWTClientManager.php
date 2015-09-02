<?php

namespace OAuth2\Client;

use Jose\JWEInterface;
use Jose\JWSInterface;
use Jose\JWTInterface;
use OAuth2\Behaviour\HasConfiguration;
use OAuth2\Behaviour\HasExceptionManager;
use OAuth2\Exception\ExceptionManagerInterface;
use Psr\Http\Message\ServerRequestInterface;
use OAuth2\Util\RequestBody;

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

        if (!$this->isClientAssertionValid($client, $assertions[0])) {
            $client_public_id_found = $client->getPublicId();
            return;
        }

        return $client;
    }

    /**
     * @param \Psr\Http\Message\ServerRequestInterface $request
     * @param string|null                              $client_public_id_found
     *
     * @return \Jose\JWEInterface|\Jose\JWEInterface[]|\Jose\JWSInterface|\Jose\JWSInterface[]|null
     * @throws \OAuth2\Exception\BaseExceptionInterface
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

        //We load the client assertion
        $jwt = $this->getJWTLoader()->load($client_assertion);

        if (!$jwt instanceof JWEInterface && !$jwt instanceof JWSInterface) {
            throw $this->getExceptionManager()->getException(ExceptionManagerInterface::BAD_REQUEST, ExceptionManagerInterface::INVALID_REQUEST, 'Parameter "client_assertion" is not a JWS or JWE.');
        }

        $this->checkAssertion($jwt);

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
        if ($jwt instanceof JWEInterface) {
            $this->loadJWE($client, $jwt);
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
     * @throws \OAuth2\Exception\BaseExceptionInterface
     */
    protected function loadJWE(JWTClientInterface $client, JWEInterface &$jwt)
    {
        if (!in_array($jwt->getEncryptionAlgorithm(), $this->getAllowedEncryptionAlgorithms()) || !in_array($jwt->getAlgorithm(), $this->getAllowedEncryptionAlgorithms())) {
            throw $this->getExceptionManager()->getException(ExceptionManagerInterface::BAD_REQUEST, ExceptionManagerInterface::INVALID_REQUEST, sprintf('Unauthorized algorithm. Please use one of the following: %s.', json_encode($this->getAllowedEncryptionAlgorithms())));
        }
        try {
            if (false === $this->getJWTLoader()->decrypt($jwt, $this->getPrivateKeySet())) {
                throw $this->getExceptionManager()->getException(ExceptionManagerInterface::BAD_REQUEST, ExceptionManagerInterface::INVALID_REQUEST, 'Unable tu decrypt the assertion.');
            }
            $jwt = $this->getJWTLoader()->load($jwt->getPayload());
        } catch (\Exception $e) {
            throw $this->getExceptionManager()->getException(ExceptionManagerInterface::BAD_REQUEST, ExceptionManagerInterface::INVALID_REQUEST, $e->getMessage());
        }
        if (!$jwt instanceof JWSInterface) {
            throw $this->getExceptionManager()->getException(ExceptionManagerInterface::BAD_REQUEST, ExceptionManagerInterface::INVALID_REQUEST, 'Encrypted token does not contain signed token.');
        }
        if ($client->getPublicId() !== $jwt->getSubject()) {
            throw $this->getExceptionManager()->getException(ExceptionManagerInterface::BAD_REQUEST, ExceptionManagerInterface::INVALID_REQUEST, 'The subject and the client must be identical.');
        }
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
}
