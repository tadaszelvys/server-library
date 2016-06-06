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
use OAuth2\Exception\Factory\AuthenticateExceptionFactory;
use OAuth2\Exception\Factory\BadRequestExceptionFactory;
use OAuth2\Exception\Factory\ExceptionFactoryInterface;
use OAuth2\Exception\Factory\NotImplementedExceptionFactory;
use OAuth2\Exception\Factory\RedirectExceptionFactory;

/**
 * An exception manager.
 *
 * @method \OAuth2\Exception\AuthenticateExceptionInterface getAuthenticateException(string $error, string $error_description = null, array $data = [])
 * @method \OAuth2\Exception\BadRequestExceptionInterface getBadRequestException(string $error, string $error_description = null, array $data = [])
 * @method \OAuth2\Exception\NotImplementedExceptionInterface getNotImplementedException(string $error, string $error_description = null, array $data = [])
 * @method \OAuth2\Exception\RedirectExceptionInterface getRedirectException(string $error, string $error_description = null, array $data = [])
 */
class ExceptionManager implements ExceptionManagerInterface
{
    /**
     * @var \OAuth2\Exception\Extension\ExceptionExtensionInterface[]
     */
    private $extensions = [];

    /**
     * @var \OAuth2\Exception\Factory\ExceptionFactoryInterface[]
     */
    private $exception_factories = [];

    public function __construct()
    {
        $this->addExceptionFactory(new AuthenticateExceptionFactory());
        $this->addExceptionFactory(new BadRequestExceptionFactory());
        $this->addExceptionFactory(new NotImplementedExceptionFactory());
        $this->addExceptionFactory(new RedirectExceptionFactory());
    }

    /**
     * {@inheritdoc}
     */
    public function addExceptionFactory(ExceptionFactoryInterface $exception_factory)
    {
        $this->exception_factories[$exception_factory->getType()] = $exception_factory;
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

        $factory = $this->getExceptionFactory($type);

        return $factory->createException($error, $error_description, $error_data, $data);
    }

    /**
     * @param string      $type
     * @param string      $error
     * @param string|null $error_description
     * @param array       $data
     *
     * @return array
     */
    private function getAdditionalErrorData($type, $error, $error_description, array $data)
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
     * @param string$type
     *
     * @throws \InvalidArgumentException
     *
     * @return \OAuth2\Exception\Factory\ExceptionFactoryInterface
     */
    private function getExceptionFactory($type)
    {
        if (array_key_exists($type, $this->exception_factories)) {
            return $this->exception_factories[$type];
        }

        throw new \InvalidArgumentException(sprintf('The exception type "%s" is not supported', $type));
    }
}
