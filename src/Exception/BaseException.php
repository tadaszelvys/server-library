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
use Psr\Http\Message\ResponseInterface;

class BaseException extends \Exception implements BaseExceptionInterface
{
    /**
     * @var array
     */
    protected $errorData;

    /**
     * @param string $code              HTTP error code
     * @param string $error             Short name of the error
     * @param string $error_description Description of the error
     * @param array  $error_data        Data to add to the error
     */
    public function __construct($code, $error, $error_description, array $error_data)
    {
        Assertion::integer($code);
        Assertion::string($error);
        Assertion::nullOrString($error_description);
        parent::__construct($error, $code);

        //Check %x20-21 / %x23-5B / %x5D-7E for error and error_description
        //Check %x21 / %x23-5B / %x5D-7E for error_uri
        $this->errorData = ['error' => $error];
        if (null !== $error_description) {
            $this->errorData['error_description'] = $error_description;
        }

        $this->errorData = array_merge(
            $this->errorData,
            $error_data
        );
    }

    /**
     * {@inheritdoc}
     */
    public function getDescription()
    {
        return array_key_exists('error_description', $this->errorData) ? $this->errorData['error_description'] : null;
    }

    /**
     * {@inheritdoc}
     */
    public function getUri()
    {
        return array_key_exists('error_uri', $this->errorData) ? urldecode($this->errorData['error_uri']) : null;
    }

    /**
     * {@inheritdoc}
     */
    public function getHttpResponse(ResponseInterface &$response)
    {
        $response->getBody()->write($this->getResponseBody());
        $response = $response->withStatus($this->getHttpCode());
        foreach ($this->getResponseHeaders() as $header => $value) {
            $response = $response->withHeader($header, $value);
        }
    }

    /**
     * {@inheritdoc}
     */
    public function getHttpCode()
    {
        return $this->getCode();
    }

    /**
     * {@inheritdoc}
     */
    public function getResponseHeaders()
    {
        return [
            'Content-Type'  => 'application/json',
            'Cache-Control' => 'no-store',
            'Pragma'        => 'no-cache',
        ];
    }

    /**
     * {@inheritdoc}
     */
    public function getResponseData()
    {
        return $this->errorData;
    }

    /**
     * {@inheritdoc}
     */
    public function getResponseBody()
    {
        return json_encode($this->getResponseData());
    }

    /**
     * Per RFC 7230, only VISIBLE ASCII characters, spaces, and horizontal tabs are allowed in values.
     *
     * @param string $text
     *
     * @return string
     */
    protected function checkHeaderValue($text)
    {
        Assertion::false(
            preg_match("#(?:(?:(?<!\r)\n)|(?:\r(?!\n))|(?:\r\n(?![ \t])))#", $text) || preg_match('/[^\x09\x0a\x0d\x20-\x7E\x80-\xFE]/', $text),
            sprintf('The header value "%s" contains invalid characters.', $text)
        );
    }
}
