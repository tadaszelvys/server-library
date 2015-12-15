<?php

namespace OAuth2\Util;

use Jose\EncrypterInterface;
use Jose\Object\EncryptionInstruction;
use Jose\JSONSerializationModes;
use Jose\Object\JWK;

final class JWTEncrypter
{
    /**
     * @var \Jose\EncrypterInterface
     */
    protected $jwt_encrypter;

    /**
     * @var \Jose\Object\JWKInterface
     */
    protected $key_encryption_key;

    /**
     * @return \Jose\EncrypterInterface
     */
    public function getJWTEncrypter()
    {
        return $this->jwt_encrypter;
    }

    /**
     * @param \Jose\EncrypterInterface $jwt_encrypter
     */
    public function setJWTEncrypter(EncrypterInterface $jwt_encrypter)
    {
        $this->jwt_encrypter = $jwt_encrypter;
    }

    /**
     * @return \Jose\Object\JWKInterface
     */
    public function getKeyEncryptionKey()
    {
        return $this->key_encryption_key;
    }

    /**
     * @param array $key_encryption_key
     */
    public function setKeyEncryptionKey(array $key_encryption_key)
    {
        $this->key_encryption_key = new JWK($key_encryption_key);
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
        $sender_key = empty($sender_key) ? null : new JWK($sender_key);
        $instruction = new EncryptionInstruction($this->getKeyEncryptionKey(), $sender_key);

        $result = $this->getJWTEncrypter()->encrypt(
            $payload,
            [$instruction],
            JSONSerializationModes::JSON_COMPACT_SERIALIZATION,
            $protected_headers
        );
        if (!is_string($result)) {
            throw new \RuntimeException('Unable to encrypt claims.');
        }

        return $result;
    }
}
