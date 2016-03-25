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
use OAuth2\Exception\Extension\ExceptionExtensionInterface;

/**
 * An exception manager.
 *
 * @method getAuthenticateException(string $error, string $error_description = null, array $data = [])
 * @method getBadRequestException(string $error, string $error_description = null, array $data = [])
 * @method getNotImplementedException(string $error, string $error_description = null, array $data = [])
 * @method getRedirectException(string $error, string $error_description = null, array $data = [])
 * @method getInternalServerErrorException(string $error, string $error_description = null, array $data = [])
 */
class ExceptionManager implements ExceptionManagerInterface
{
    /**
     * @var \OAuth2\Exception\Extension\ExceptionExtensionInterface[]
     */
    private $extensions = [];
    
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
    public function addExtension(ExceptionExtensionInterface $extension)
    {
        $this->extensions[] = $extension;
    }

    /**
     * {@inheritdoc}
     */
    public function getException($type, $error, $error_description = null, array $data = [])
    {
        Assertion::string($type);
        Assertion::string($error);
        Assertion::nullOrString($error_description);

        $error_data = $this->getAdditionalErrorData($type, $error, $error_description, $data);

        $supported_types = $this->getExceptionTypeMap();

        if (array_key_exists($type, $supported_types)) {
            $class = $supported_types[$type];

            return new $class($error, $error_description, $error_data, $data);
        }

        throw new \InvalidArgumentException('Unsupported type');
    }

    /**
     * @param string       $type
     * @param string       $error
     * @param string|null  $error_description
     * @param array        $data
     *
     * @return array
     */
    private function getAdditionalErrorData($type, $error, $error_description = null, array $data)
    {
        $result = [];
        foreach ($this->extensions as $extension) {
            $result = array_merge(
                $result,
                $extension->getData($type, $error, $error_description, $data)
            );
        }

        return $result;
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
