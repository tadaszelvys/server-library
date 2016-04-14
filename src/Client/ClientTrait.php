<?php

/*
 * The MIT License (MIT)
 *
 * Copyright (c) 2014-2016 Spomky-Labs
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file for details.
 */

namespace OAuth2\Client;

use Assert\Assertion;
use Jose\Factory\JWKFactory;
use Jose\Object\JWK;
use Jose\Object\JWKSet;

trait ClientTrait
{
    /**
     * @var array
     */
    private $metadatas = [];

    /**
     * @var int
     */
    private $client_secret_expires_at = 0;

    /**
     * @var string
     */
    private $token_endpoint_auth_method = 'client_secret_basic';

    /**
     * @param string $name
     * @param $arguments
     *
     * @return mixed
     */
    public function __call($name, array $arguments)
    {
        if (method_exists($this, $name)) {
            return call_user_func([$this, $name], $arguments);
        }

        $method = mb_substr($name, 0, 3, '8bit');
        if (in_array($method, ['get', 'set', 'has'])) {
            $key = $this->decamelize(mb_substr($name, 3, null, '8bit'));
            $arguments = array_merge(
                [$key],
                $arguments
            );

            return call_user_func_array([$this, $method], $arguments);
        }
        throw new \BadMethodCallException(sprintf('Method "%s" does not exists.', $name));
    }

    /**
     * {@inheritdoc}
     */
    public function has($key)
    {
        Assertion::string($key);

        return property_exists($this, $key) || array_key_exists($key, $this->metadatas);
    }

    /**
     * {@inheritdoc}
     */
    public function get($key)
    {
        Assertion::true($this->has($key), sprintf('Configuration value with key "%s" does not exist.', $key));

        return property_exists($this, $key) ? $this->$key : $this->metadatas[$key];
    }

    /**
     * {@inheritdoc}
     */
    public function set($key, $value)
    {
        Assertion::string($key);
        if (property_exists($this, $key)) {
            $this->$key = $value;
        } else {
            $this->metadatas[$key] = $value;
        }
    }

    /**
     * {@inheritdoc}
     */
    public function remove($key)
    {
        if (true === $this->has($key)) {
            unset($this->metadatas[$key]);
        }
    }

    /**
     * {@inheritdoc}
     */
    public function isGrantTypeAllowed($grant_type)
    {
        Assertion::string($grant_type, 'Argument must be a string.');
        $grant_types = $this->get('grant_types');
        Assertion::isArray($grant_types, 'The metadata "grant_types" must be an array.');

        return in_array($grant_type, $grant_types);
    }

    /**
     * {@inheritdoc}
     */
    public function isResponseTypeAllowed($response_type)
    {
        Assertion::string($response_type, 'Argument must be a string.');
        $response_types = $this->get('response_types');
        Assertion::isArray($response_types, 'The metadata "response_types" must be an array.');
        
        return in_array($response_type, $response_types);
    }

    /**
     * {@inheritdoc}
     */
    public function isTokenTypeAllowed($token_type)
    {
        Assertion::string($token_type, 'Argument must be a string.');
        if (!$this->has('token_types')) {
            return true;
        }
        $token_types = $this->get('token_types');
        Assertion::isArray($token_types, 'The metadata "token_types" must be an array.');

        return in_array($token_type, $token_types);
    }

    /**
     * {@inheritdoc}
     */
    public function isPublic()
    {
        return 'none' === $this->getTokenEndpointAuthMethod();
    }

    /**
     * {@inheritdoc}
     */
    public function areClientCredentialsExpired()
    {
        if (0 === $this->client_secret_expires_at) {
            return false;
        }

        return time() > $this->client_secret_expires_at;
    }



    /**
     * @return bool
     */
    public function hasPublicKeySet()
    {
        return $this->has('jwks') || $this->has('jwks_uri') || $this->hasClientSecret();
    }

    /**
     * @return \Jose\Object\JWKSetInterface
     */
    public function getPublicKeySet()
    {
        Assertion::true($this->hasPublicKeySet(), 'The client has no public key set');
        
        if ($this->has('jwks')) {
            return new JWKSet($this->get('jwks'), true);
        }
        if ($this->has('jwks_uri')) {
            return JWKFactory::createFromJKU($this->get('jwks_uri'));
        }
        
        $jwk_set = new JWKSet();
        $jwk_set->addKey(new JWK([
            'kty' => 'oct',
            'use' => 'sig',
            'k'   => $this->getClientSecret(),
        ]));
        
        return $jwk_set;
    }

    /**
     * @param string $word
     *
     * @return string
     */
    private function decamelize($word)
    {
        return preg_replace_callback(
            '/(^|[a-z])([A-Z])/',
            function ($m) { return mb_strtolower(mb_strlen($m[1], '8bit') ? sprintf('%s_%s', $m[1], $m[2]) : $m[2], '8bit'); },
            $word
        );
    }
}
