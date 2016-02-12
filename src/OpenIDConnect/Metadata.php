<?php

namespace OAuth2\OpenIDConnect;

use Assert\Assertion;

final class Metadata implements \JsonSerializable
{
    /**
     * @var array
     */
    private $values = [];

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

        $method = substr($name, 0, 3);
        if (in_array($method, ['get', 'set'])) {

            $key = $this->decamelize(substr($name, 3));
            $arguments = array_merge(
                [$key],
                $arguments
            );
            return call_user_func_array([$this, $method], $arguments);
        }
        throw new \BadMethodCallException(sprintf('Method "%s" does not exists.', $name));
    }

    /**
     * @param string $key
     *
     * @return bool
     */
    public function has($key)
    {
        Assertion::string($key);
        return array_key_exists($key, $this->values);
    }

    /**
     * @param string $key
     *
     * @return mixed
     */
    public function get($key)
    {
        if (true === $this->has($key)) {
            return $this->values[$key];
        }

        throw new \InvalidArgumentException(sprintf('Configuration value with key "%s" does not exist.', $key));
    }

    /**
     * @param string $key
     * @param mixed  $value
     */
    public function set($key, $value)
    {
        Assertion::string($key);
        $this->values[$key] = $value;
    }

    /**
     * @param $key
     */
    public function remove($key)
    {
        if (true === $this->has($key)) {
            unset($this->values[$key]);
        }
    }

    /**
     * @param string $word
     *
     * @return string
     */
    private function decamelize($word) {
        return $word = preg_replace_callback(
            "/(^|[a-z])([A-Z])/",
            function($m) { return strtolower(strlen($m[1]) ? "$m[1]_$m[2]" : "$m[2]"); },
            $word
        );

    }

    /**
     * {@inheritdoc}
     */
    function jsonSerialize()
    {
        return $this->values;
    }
}
