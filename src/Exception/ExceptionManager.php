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
     * @var array
     */
    private $exception_map = [];

    public function __construct()
    {
        $this->exception_map = [
            self::AUTHENTICATE    => AuthenticateException::class,
            self::BAD_REQUEST     => BadRequestException::class,
            self::NOT_IMPLEMENTED => NotImplementedException::class,
            self::REDIRECT        => RedirectException::class,
        ];
    }

    /**
     * {@inheritdoc}
     */
    public function addExceptionType($name, $exception_class)
    {
        Assertion::string($name);
        Assertion::string($exception_class);
        Assertion::classExists($exception_class);
        $this->exception_map[$name] = $exception_class;
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
        if (0 === mb_strpos($name, 'get', null, '8bit') && 'Exception' === mb_substr($name, -9, null, '8bit')) {
            $arguments = array_merge(
                [mb_substr($name, 3, mb_strlen($name, '8bit') - 12, '8bit')],
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

        $class = $this->getExceptionType($type);

        return new $class($error, $error_description, $error_data, $data);
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
     * @param string $type
     *
     * @return string
     */
    private function getExceptionType($type)
    {
        if (array_key_exists($type, $this->exception_map)) {
            return $this->exception_map[$type];
        }

        throw new \InvalidArgumentException(sprintf('The exception type "%s" is not supported', $type));
    }
}
