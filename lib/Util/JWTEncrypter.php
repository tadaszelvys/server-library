<?php

namespace OAuth2\Util;

use Jose\EncrypterInterface;
use Jose\JSONSerializationModes;
use Jose\JWKInterface;
use Jose\JWKManagerInterface;
use SpomkyLabs\Jose\EncryptionInstruction;

class JWTEncrypter
{
    /**
     * @var \Jose\EncrypterInterface
     */
    protected $jwt_encrypter;

    /**
     * @var \Jose\JWKManagerInterface
     */
    protected $key_manager;

    /**
     * @var \Jose\JWKSetInterface
     */
    protected $key_encryption_key;

    /**
     * @return \Jose\JWKManagerInterface
     */
    public function getKeyManager()
    {
        return $this->key_manager;
    }

    /**
     * @param  $key_manager
     *
     * @return self
     */
    public function setKeyManager(JWKManagerInterface $key_manager)
    {
        $this->key_manager = $key_manager;

        return $this;
    }

    /**
     * @return \Jose\EncrypterInterface
     */
    public function getJWTEncrypter()
    {
        return $this->jwt_encrypter;
    }

    /**
     * @param \Jose\EncrypterInterface $jwt_encrypter
     *
     * @return self
     */
    public function setJWTEncrypter(EncrypterInterface $jwt_encrypter)
    {
        $this->jwt_encrypter = $jwt_encrypter;

        return $this;
    }

    /**
     * @return \Jose\JWKInterface
     */
    public function getKeyEncryptionKey()
    {
        return $this->key_encryption_key;
    }

    /**
     * @param array $key_encryption_key
     *
     * @return self
     */
    public function setKeyEncryptionKey(array $key_encryption_key)
    {
        $this->key_encryption_key = $this->getKeyManager()->createJWK($key_encryption_key);

        return $this;
    }

    /**
     * @param string $payload
     * @param array  $protected_headers
     * @param array  $sender_key
     *
     * @return string
     */
    public function encrypt($payload, array $protected_headers, array $sender_key = [])
    {
        $sender_key = empty($sender_key)?null:$this->getKeyManager()->createJWK($sender_key);
        $instruction = new EncryptionInstruction();
        $instruction->setRecipientKey($this->getKeyEncryptionKey());
        if ($sender_key instanceof JWKInterface) {
            $instruction->setSenderKey($sender_key);
        }

        $result = $this->getJWTEncrypter()->encrypt($payload, [$instruction], $protected_headers, [], JSONSerializationModes::JSON_COMPACT_SERIALIZATION);
        if (!is_string($result)) {
            throw new \RuntimeException('Unable to sign claims.');
        }
        return $result;
    }
}
