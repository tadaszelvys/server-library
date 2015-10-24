<?php

namespace OAuth2\Util;

use Jose\JWEInterface;
use Jose\JWKSetManagerInterface;
use Jose\JWSInterface;
use Jose\JWTInterface;
use Jose\LoaderInterface;
use OAuth2\Behaviour\HasExceptionManager;
use OAuth2\Client\JWTClientInterface;
use OAuth2\Exception\ExceptionManagerInterface;

class JWTLoader
{
    use HasExceptionManager;

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
     * @var \Jose\JWKSetInterface
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
     * @return \Jose\JWKSetInterface
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
        $this->private_key_set = $this->getKeySetManager()->createJWKSet($private_key_set);

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
     * @param $assertion
     *
     * @return \Jose\JWSInterface|\Jose\JWEInterface
     * @throws \OAuth2\Exception\BaseExceptionInterface
     */
    public function load($assertion)
    {
        //We load the assertion
        $jwt = $this->loadAssertion($assertion);
        if ($jwt instanceof JWEInterface) {
            $this->verifyAssertion($jwt);
            $jwt = $this->decryptAssertion($jwt);
        }
        $this->verifyAssertion($jwt);

        return $jwt;
    }

    /**
     * @param string $assertion
     *
     * @throws \OAuth2\Exception\BaseExceptionInterface
     *
     * @return JWTInterface
     */
    protected function loadAssertion($assertion)
    {
        $jwt = $this->getJWTLoader()->load($assertion);
        if (!$jwt instanceof JWEInterface && !$jwt instanceof JWSInterface) {
            throw $this->getExceptionManager()->getException(ExceptionManagerInterface::BAD_REQUEST, ExceptionManagerInterface::INVALID_REQUEST, 'The assertion does not contain a single JWS or a single JWE.');
        }

        return $jwt;
    }

    /**
     * @param \Jose\JWEInterface $jwe
     *
     * @throws \OAuth2\Exception\BaseExceptionInterface
     *
     * @return \Jose\JWSInterface
     */
    protected function decryptAssertion(JWEInterface $jwe)
    {
        if (!in_array($jwe->getAlgorithm(), $this->getAllowedEncryptionAlgorithms()) || !in_array($jwe->getEncryptionAlgorithm(), $this->getAllowedEncryptionAlgorithms())) {
            throw $this->getExceptionManager()->getException(ExceptionManagerInterface::BAD_REQUEST, ExceptionManagerInterface::INVALID_REQUEST, sprintf('Algorithm not allowed. Authorized algorithms: %s.', json_encode($this->getAllowedEncryptionAlgorithms())));
        }
        $this->getJWTLoader()->decrypt($jwe, $this->getPrivateKeySet());
        if (null == $jwe->getPayload()) {
            throw $this->getExceptionManager()->getException(ExceptionManagerInterface::BAD_REQUEST, ExceptionManagerInterface::INVALID_REQUEST, 'Unable to decrypt the payload. Please verify keys used for encryption.');
        }
        $jws = $this->getJWTLoader()->load($jwe->getPayload());
        if (!$jws instanceof JWSInterface) {
            throw $this->getExceptionManager()->getException(ExceptionManagerInterface::BAD_REQUEST, ExceptionManagerInterface::INVALID_REQUEST, 'The encrypted assertion does not contain a single JWS.');
        }

        return $jws;
    }

    /**
     * @param \Jose\JWSInterface                $jws
     * @param \OAuth2\Client\JWTClientInterface $client
     *
     * @throws \OAuth2\Exception\BaseExceptionInterface
     */
    public function verifySignature(JWSInterface $jws, JWTClientInterface $client)
    {
        if (!in_array($jws->getAlgorithm(), $client->getAllowedSignatureAlgorithms())) {
            throw $this->getExceptionManager()->getException(ExceptionManagerInterface::BAD_REQUEST, ExceptionManagerInterface::INVALID_REQUEST, sprintf('Algorithm not allowed. Authorized algorithms: %s.', json_encode($client->getAllowedSignatureAlgorithms())));
        }

        if (false === $this->getJWTLoader()->verifySignature($jws, $this->getPrivateKeySet())) {
            throw $this->getExceptionManager()->getException(ExceptionManagerInterface::BAD_REQUEST, ExceptionManagerInterface::INVALID_REQUEST, 'Invalid signature.');
        }
    }

    /**
     * @param \Jose\JWTInterface $jwt
     *
     * @throws \OAuth2\Exception\BaseExceptionInterface
     */
    public function verifyAssertion(JWTInterface $jwt)
    {
        foreach ($this->getRequiredClaims() as $claim) {
            if (null === $jwt->getHeaderOrPayloadValue($claim)) {
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
}
