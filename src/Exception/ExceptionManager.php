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
     * @var string
     */
    private $realm;

    /**
     * ExceptionManager constructor.
     *
     * @param string $realm
     */
    public function __construct($realm)
    {
        Assertion::string($realm);
        $this->realm = $realm;
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
        if ($type === self::AUTHENTICATE && !isset($data['realm'])) {
            $data['realm'] = $this->realm;
        }

        $error_uri = $this->getUri($type, $error, $error_description, $data);

        $supported_types = [
            self::AUTHENTICATE,
            self::BAD_REQUEST,
            self::NOT_IMPLEMENTED,
            self::REDIRECT,
            self::INTERNAL_SERVER_ERROR,
        ];

        if (in_array($type, $supported_types)) {
            $exception = sprintf('OAuth2\Exception\%sException', $type);

            return new $exception($error, $error_description, $error_uri, $data);
        }

        throw new \InvalidArgumentException('Unsupported type');
    }
}
