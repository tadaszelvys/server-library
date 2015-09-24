<?php

namespace OAuth2\Util;

use Jose\EncrypterInterface;
use Jose\JWKManagerInterface;
use Jose\JWKSetManagerInterface;
use Jose\LoaderInterface;
use Jose\SignerInterface;
use OAuth2\Client\ClientInterface;

class JWTFactory
{
    /**
     * @var \Jose\LoaderInterface
     */
    protected $loader;

    /**
     * @var \Jose\SignerInterface
     */
    protected $signer;

    /**
     * @var \Jose\EncrypterInterface
     */
    protected $encrypter;

    /**
     * @var \Jose\JWKManagerInterface
     */
    protected $key_manager;

    /**
     * @var \Jose\JWKSetManagerInterface
     */
    protected $key_set_manager;

    /**
     * @return \Jose\LoaderInterface
     */
    public function getLoader()
    {
        return $this->loader;
    }

    /**
     * @param \Jose\LoaderInterface $loader
     *
     * @return self
     */
    public function setLoader(LoaderInterface $loader)
    {
        $this->loader = $loader;

        return $this;
    }

    /**
     * @return \Jose\SignerInterface
     */
    public function getSigner()
    {
        return $this->signer;
    }

    /**
     * @param \Jose\SignerInterface $signer
     *
     * @return self
     */
    public function setSigner(SignerInterface $signer)
    {
        $this->signer = $signer;

        return $this;
    }

    /**
     * @return \Jose\EncrypterInterface|null
     */
    public function getEncrypter()
    {
        return $this->encrypter;
    }

    /**
     * @param \Jose\EncrypterInterface $encrypter
     *
     * @return self
     */
    public function setEncrypter(EncrypterInterface $encrypter)
    {
        $this->encrypter = $encrypter;

        return $this;
    }

    /**
     * @return \Jose\JWKManagerInterface
     */
    public function getKeyManager()
    {
        return $this->key_manager;
    }

    /**
     * @param \Jose\JWKManagerInterface $key_manager
     *
     * @return self
     */
    public function setKeyManager(JWKManagerInterface $key_manager)
    {
        $this->key_manager = $key_manager;

        return $this;
    }

    /**
     * @return \Jose\JWKSetManagerInterface
     */
    public function getKeySetManager()
    {
        return $this->key_set_manager;
    }

    /**
     * @param \Jose\JWKSetManagerInterface $key_set_manager
     *
     * @return self
     */
    public function setKeySetManager(JWKSetManagerInterface $key_set_manager)
    {
        $this->key_set_manager = $key_set_manager;

        return $this;
    }

    /**
     * @param array $payload
     *
     * @throws \OAuth2\Exception\BaseExceptionInterface
     *
     * @return string
     */
    public function sign(array $payload)
    {
    }

    /**
     * @param string                         $payload
     * @param \OAuth2\Client\ClientInterface $client
     *
     * @throws \OAuth2\Exception\BaseExceptionInterface
     *
     * @return string
     */
    public function encrypt($payload, ClientInterface $client)
    {
    }
}
