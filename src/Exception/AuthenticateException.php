<?php

/*
 * The MIT License (MIT)
 *
 * Copyright (c) 2014-2015 Spomky-Labs
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file for details.
 */

namespace OAuth2\Exception;

final class AuthenticateException extends BaseException implements AuthenticateExceptionInterface
{
    private $header = [];

    /**
     * @param string $error             Short name of the error
     * @param string $error_description Description of the error (optional)
     * @param string $error_uri         Uri of the error (optional)
     * @param array  $data              Additional data sent to the exception (optional)
     */
    public function __construct($error, $error_description = null, $error_uri = null, array $data = [])
    {
        parent::__construct(401, $error, $error_description, $error_uri);

        if (!isset($data['schemes'])) {
            throw new \InvalidArgumentException('schemes_not_defined');
        }

        $schemes = [];
        foreach ($data['schemes'] as $scheme => $values) {
            if (empty($values)) {
                $schemes[] = $scheme;
            } else {
                $result = [];
                foreach ($values as $key => $value) {
                    $result[] = sprintf('%s=%s', $key, $this->quote($value));
                }
                $schemes[] = $scheme.' '.implode(',', $result);
            }
        }

        $this->header = ['WWW-Authenticate' => $schemes];
    }

    /**
     * {@inheritdoc}
     */
    public function getResponseHeaders()
    {
        return array_merge(parent::getResponseHeaders(), $this->header);
    }

    /**
     * {@inheritdoc}
     */
    public function getResponseBody()
    {
    }

    /**
     * Per RFC 7230, only VISIBLE ASCII characters, spaces, and horizontal tabs are allowed in values
     * 
     * @param string $text
     *
     * @return string
     */
    private function quote($text)
    {
        $text = preg_replace("#(?:(?:(?<!\r)\n)|(?:\r(?!\n))|(?:\r\n(?![ \t])))#", '', $value);
        $text = preg_replace('/[^\x09\x0a\x0d\x20-\x7E\x80-\xFE]/', '', $text);
        $text = addcslashes($text, '"\\');

        return sprintf('"%s"', $text);
    }
}
