<?php

namespace OAuth2\Client;

use Jose\JWEInterface;
use Jose\JWKSetManagerInterface;
use Jose\JWSInterface;
use Jose\JWTInterface;
use Jose\LoaderInterface;
use OAuth2\Behaviour\HasConfiguration;
use OAuth2\Behaviour\HasExceptionManager;
use OAuth2\Exception\ExceptionManagerInterface;
use OAuth2\Util\RequestBody;
use Psr\Http\Message\ServerRequestInterface;

abstract class JWTClientManager implements ClientManagerInterface
{
    use HasExceptionManager;
    use HasConfiguration;

    /**
     * @var \Jose\LoaderInterface
     */
    protected $jwt_loader;

    /**
     * @var \Jose\JWKSetManagerInterface
     */
    protected $key_set_manager;

    /**
     * @var string[]
     */
    protected $allowed_encryption_algorithms = [];

    /**
     * @var array
     */
    protected $private_key_set;

    /**
     * @return \Jose\JWKSetManagerInterface
     */
    public function getKeySetManager()
    {
        return $this->key_set_manager;
    }

    /**
     * @param  $key_set_manager
     *
     * @return self
     */
    public function setKeySetManager(JWKSetManagerInterface $key_set_manager)
    {
        $this->key_set_manager = $key_set_manager;

        return $this;
    }

    /**
     * @return \Jose\LoaderInterface
     */
    public function getJWTLoader()
    {
        return $this->jwt_loader;
    }

    /**
     * @param \Jose\LoaderInterface $jwt_loader
     *
     * @return self
     */
    public function setJWTLoader(LoaderInterface $jwt_loader)
    {
        $this->jwt_loader = $jwt_loader;

        return $this;
    }

    /**
     * @return array
     */
    public function getPrivateKeySet()
    {
        return $this->private_key_set;
    }

    /**
     * @param array $private_key_set
     *
     * @return self
     */
    public function setPrivateKeySet(array $private_key_set)
    {
        $this->private_key_set = $private_key_set;

        return $this;
    }

    /**
     * @return string[]
     */
    public function getAllowedEncryptionAlgorithms()
    {
        return $this->allowed_encryption_algorithms;
    }

    /**
     * @param string[] $allowed_encryption_algorithms
     *
     * @return self
     */
    public function setAllowedEncryptionAlgorithms(array $allowed_encryption_algorithms)
    {
        $this->allowed_encryption_algorithms = $allowed_encryption_algorithms;

        return $this;
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
     * @throws \OAuth2\Exception\BaseExceptionInterface
     *
     * @return \Jose\JWEInterface|\Jose\JWEInterface[]|\Jose\JWSInterface|\Jose\JWSInterface[]|null
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
     * By default, this method does nothing, but should be overridden and check other claims (issuer, jti...).
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
     * @throws \OAuth2\Exception\BaseExceptionInterface
     *
     * @return bool
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
        $keyset = $this->getKeySetManager()->createJWKSet($client->getSignaturePublicKeySet());

        $is_signature_verified = $this->getJWTLoader()->verifySignature($jwt, $keyset);

        return $is_signature_verified;
    }

    /**
     * @param \OAuth2\Client\JWTClientInterface $client
     * @param \Jose\JWEInterface                $jwt
     *
     * @throws \OAuth2\Exception\BaseExceptionInterface
     */
    protected function loadJWE(JWTClientInterface $client, JWEInterface &$jwt)
    {
        if (!in_array($jwt->getEncryptionAlgorithm(), $this->getAllowedEncryptionAlgorithms()) || !in_array($jwt->getAlgorithm(), $this->getAllowedEncryptionAlgorithms())) {
            throw $this->getExceptionManager()->getException(ExceptionManagerInterface::BAD_REQUEST, ExceptionManagerInterface::INVALID_REQUEST, sprintf('Unauthorized algorithm. Please use one of the following: %s.', json_encode($this->getAllowedEncryptionAlgorithms())));
        }
        try {
            $private_keyset = $this->getKeySetManager()->createJWKSet($this->getPrivateKeySet());
            if (false === $this->getJWTLoader()->decrypt($jwt, $private_keyset)) {
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
        } catch (\Exception $e) {
            throw $this->getExceptionManager()->getException(ExceptionManagerInterface::BAD_REQUEST, ExceptionManagerInterface::INVALID_REQUEST, $e->getMessage());
        }

        $this->checkJWT($jwt);
    }
}
