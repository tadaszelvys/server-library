<?php

namespace OAuth2\Util;

use Jose\JWEInterface;
use Jose\JWKSetManager;
use Jose\JWSInterface;
use Jose\JWTInterface;
use Jose\LoaderInterface;
use OAuth2\Behaviour\HasExceptionManager;
use OAuth2\Client\JWTClientInterface;
use OAuth2\Exception\ExceptionManagerInterface;

final class JWTLoader
{
    use HasExceptionManager;

    /**
     * @var bool
     */
    protected $is_encryption_required = false;

    /**
     * @var \Jose\LoaderInterface
     */
    protected $jwt_loader;

    /**
     * @var string[]
     */
    protected $allowed_encryption_algorithms = [];

    /**
     * @var \Jose\JWKSetInterface
     */
    protected $key_set;

    /**
     * @return \Jose\JWKSetManagerInterface
     */
    public function getKeySetManager()
    {
        return new JWKSetManager();
    }

    /**
     * @return bool
     */
    public function isEncryptionRequired()
    {
        return $this->is_encryption_required;
    }

    /**
     * @param bool $is_encryption_required
     *
     * @return self
     */
    public function setEncryptionRequired($is_encryption_required)
    {
        $this->is_encryption_required = $is_encryption_required;

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
    public function getKeySet()
    {
        return $this->key_set;
    }

    /**
     * @param array $key_set
     *
     * @return self
     */
    public function setKeySet(array $key_set)
    {
        $this->key_set = $this->getKeySetManager()->createJWKSet($key_set);

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
     * @throws \OAuth2\Exception\BaseExceptionInterface
     *
     * @return \Jose\JWSInterface|\Jose\JWEInterface
     */
    public function load($assertion)
    {
        //We load the assertion
        $jwt = $this->loadAssertion($assertion);
        if ($jwt instanceof JWEInterface) {
            $this->verifyAssertion($jwt);
            $jwt = $this->decryptAssertion($jwt);
        } elseif (true === $this->isEncryptionRequired()) {
            throw $this->getExceptionManager()->getException(ExceptionManagerInterface::BAD_REQUEST, ExceptionManagerInterface::INVALID_REQUEST, 'The assertion must be encrypted.');
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
        $this->getJWTLoader()->decrypt($jwe, $this->getKeySet());
        if (null === $jwe->getPayload()) {
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

        if (false === $this->getJWTLoader()->verifySignature($jws, $this->getKeySet())) {
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
        try {
            $this->getJWTLoader()->verify($jwt);
        } catch (\Exception $e) {
            throw $this->getExceptionManager()->getException(ExceptionManagerInterface::BAD_REQUEST, ExceptionManagerInterface::INVALID_REQUEST, $e->getMessage());
        }

        $this->checkJWT($jwt);
    }

    /**
     * By default, this method does nothing, but should be overridden and to check claims and headers.
     *
     * @param \Jose\JWTInterface $jwt
     *
     * @throws \OAuth2\Exception\BaseExceptionInterface
     */
    protected function checkJWT(JWTInterface $jwt)
    {
    }
}
