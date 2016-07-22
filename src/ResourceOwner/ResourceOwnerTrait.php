<?php

/*
 * The MIT License (MIT)
 *
 * Copyright (c) 2014-2016 Spomky-Labs
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file for details.
 */

namespace OAuth2\ResourceOwner;

use Assert\Assertion;
use Base64Url\Base64Url;

trait ResourceOwnerTrait
{
    /**
     * @var array
     */
    protected $metadatas = [];

    /**
     * @var string
     */
    protected $public_id;

    /**
     * ResourceOwnerTrait constructor.
     */
    public function __construct()
    {
        $this->setPublicId(Base64Url::encode(random_bytes(50)));
    }

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
    public function all()
    {
        return $this->metadatas;
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
    public function getPublicId()
    {
        return $this->public_id;
    }

    /**
     * {@inheritdoc}
     */
    public function setPublicId($public_id)
    {
        $this->public_id = $public_id;
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
            function ($m) {
                return mb_strtolower(mb_strlen($m[1], '8bit') ? sprintf('%s_%s', $m[1], $m[2]) : $m[2], '8bit');
            },
            $word
        );
    }
}
