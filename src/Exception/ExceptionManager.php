<?php

/*
 * The MIT License (MIT)
 *
 * Copyright (c) 2014-2016 Spomky-Labs
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file for details.
 */

namespace OAuth2\Exception;

use Assert\Assertion;

/**
 * An exception manager.
 */
class ExceptionManager implements ExceptionManagerInterface
{
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
        if (0 === strpos($name, 'get') && 'Exception' === substr($name, -9)) {
            $arguments = array_merge(
                [substr($name, 3, strlen($name) - 12)],
                $arguments
            );

            return call_user_func_array([$this, 'getException'], $arguments);
        }
        throw new \BadMethodCallException(sprintf('Method "%s" does not exists.', $name));
    }

    /**
     * {@inheritdoc}
     */
    public function getUri($type, $error, $error_description = null, array $data = [])
    {
    }

    /**
     * {@inheritdoc}
     */
    public function getException($type, $error, $error_description = null, array $data = [])
    {
        Assertion::string($type);
        Assertion::string($error);
        Assertion::nullOrString($error_description);

        $error_uri = $this->getUri($type, $error, $error_description, $data);

        $supported_types = $this->getExceptionTypeMap();

        if (array_key_exists($type, $supported_types)) {
            $class = $supported_types[$type];

            return new $class($error, $error_description, $error_uri, $data);
        }

        throw new \InvalidArgumentException('Unsupported type');
    }

    /**
     * @return array
     */
    protected function getExceptionTypeMap()
    {
        return [
            self::AUTHENTICATE          => 'OAuth2\Exception\AuthenticateException',
            self::BAD_REQUEST           => 'OAuth2\Exception\BadRequestException',
            self::NOT_IMPLEMENTED       => 'OAuth2\Exception\NotImplementedException',
            self::REDIRECT              => 'OAuth2\Exception\RedirectException',
        ];
    }
}
