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
use OAuth2\Grant\ResponseTypeSupportInterface;
use OAuth2\Util\Uri;

final class RedirectException extends BaseException implements RedirectExceptionInterface
{
    /**
     * @var string
     */
    private $redirect_uri;

    /**
     * @var string
     */
    private $transport_mode;

    /**
     * @param string $error             Short name of the error
     * @param string $error_description Description of the error (optional)
     * @param string $error_uri         Uri of the error (optional)
     * @param array  $data              Additional data sent to the exception (optional)
     *
     * @throws \InvalidArgumentException
     */
    public function __construct($error, $error_description = null, $error_uri = null, array $data = [])
    {
        parent::__construct(302, $error, $error_description, $error_uri);

        Assertion::keyExists($data, 'redirect_uri', 'redirect_uri_not_defined');
        Assertion::false(
            !array_key_exists('transport_mode', $data) || !in_array($data['transport_mode'], [ResponseTypeSupportInterface::RESPONSE_TYPE_MODE_FRAGMENT, ResponseTypeSupportInterface::RESPONSE_TYPE_MODE_QUERY]),
            'invalid_transport_mode'
        );
        $this->transport_mode = $data['transport_mode'];

        $this->redirect_uri = $data['redirect_uri'];

        if (array_key_exists('state', $data) && null !== $data['state']) {
            $this->errorData['state'] = $data['state'];
        }
    }

    /**
     * {@inheritdoc}
     */
    public function getResponseBody()
    {
    }

    /**
     * {@inheritdoc}
     */
    public function getResponseHeaders()
    {
        $data = $this->errorData;
        if (array_key_exists('error_uri', $data)) {
            $data['error_uri'] = urldecode($data['error_uri']);
        }
        $params = [$this->transport_mode => $data];
        $uri = Uri::buildURI($this->redirect_uri, $params);
        $this->checkHeaderValue($uri);

        return [
            'Location'                => $uri.'#',           // The fragment '#' is used to mitigate closing redirectors
            'Content-Security-Policy' => 'referrer origin;', // The header is used to mitigate closing redirectors
        ];
    }
}
