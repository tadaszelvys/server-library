<?php declare(strict_types=1);

/*
 * The MIT License (MIT)
 *
 * Copyright (c) 2014-2016 Spomky-Labs
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file for details.
 */

namespace OAuth2\Model\ResourceOwner;

use Assert\Assertion;

abstract class ResourceOwner implements \JsonSerializable
{
    /**
     * @var array
     */
    private $metadatas = [];

    /**
     * ResourceOwner constructor.
     *
     * @param array $metadatas
     */
    protected function __construct(array $metadatas)
    {
        $this->metadatas = $metadatas;
    }

    /**
     * @param string $name
     * @param $arguments
     *
     * @return mixed
     */
    public function __call(string $name, array $arguments): mixed
    {
        if (method_exists($this, $name)) {
            return call_user_func([$this, $name], $arguments);
        }

        $method = mb_substr($name, 0, 3, '8bit');
        if (in_array($method, ['get', 'has'])) {
            $key = $this->decamelize(mb_substr($name, 3, null, '8bit'));
            $arguments = array_merge([$key], $arguments);

            return call_user_func_array([$this, $method], $arguments);
        }
        throw new \BadMethodCallException(sprintf('Method \'%s\' does not exists.', $name));
    }

    /**
     * @return array
     */
    public function all(): array
    {
        return $this->metadatas;
    }

    /**
     * @param string $key
     *
     * @return bool
     */
    public function has(string $key): bool
    {
        Assertion::string($key);

        return array_key_exists($key, $this->metadatas);
    }

    /**
     * {@inheritdoc}
     */
    public function get(string $key)
    {
        Assertion::true($this->has($key), sprintf('Configuration value with key \'%s\' does not exist.', $key));

        return $this->metadatas[$key];
    }

    /**
     * @param string $word
     *
     * @return string
     */
    private function decamelize(string $word)
    {
        return preg_replace_callback(
            '/(^|[a-z])([A-Z])/',
            function ($m) {
                return mb_strtolower(mb_strlen($m[1], '8bit') ? sprintf('%s_%s', $m[1], $m[2]) : $m[2], '8bit');
            },
            $word
        );
    }

    /**
     * @return array
     */
    public function jsonSerialize(): array
    {
        return $this->all();
    }
}
