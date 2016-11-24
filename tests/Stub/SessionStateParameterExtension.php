<?php

/*
 * The MIT License (MIT)
 *
 * Copyright (c) 2014-2016 Spomky-Labs
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file for details.
 */

namespace OAuth2\Test\Stub;

use Base64Url\Base64Url;
use OAuth2\Endpoint\Authorization\AuthorizationInterface;
use OAuth2\OpenIdConnect\SessionManagement\SessionStateParameterExtension as Base;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Symfony\Component\HttpFoundation\Cookie;

final class SessionStateParameterExtension extends Base
{
    /**
     * @var string
     */
    private $storage_name;

    /**
     * SessionStateParameterExtension constructor.
     *
     * @param string $storage_name
     */
    public function __construct($storage_name)
    {
        $this->storage_name = $storage_name;
    }

    /**
     * {@inheritdoc}
     */
    public function getBrowserState(ServerRequestInterface $request)
    {
        $browser_state = array_key_exists($this->storage_name, $_SESSION) ? $_SESSION[$this->storage_name] : null;

        return $browser_state;
    }

    /**
     * {@inheritdoc}
     */
    protected function saveBrowserState($browser_state)
    {
        $_SESSION[$this->storage_name] = $browser_state;

        $cookie = new Cookie($this->storage_name, $browser_state);
        $response = $response->withAddedHeader('Set-Cookie', (string) $cookie);
    }

    /**
     * {@inheritdoc}
     */
    protected function generateBrowserState()
    {
        return Base64Url::encode(random_bytes(64));
    }

    /**
     * {@inheritdoc}
     */
    protected function calculateSessionState(ServerRequestInterface $request, AuthorizationInterface $authorization, $browser_state)
    {
        $origin = $this->getOriginUri($authorization->getRedirectUri());
        $salt = Base64Url::encode(random_bytes(16));
        $hash = hash('sha256', sprintf(
            '%s%s%s%s',
            $authorization->getClient()->getPublicId(),
            $origin,
            $browser_state,
            $salt
        ));

        return sprintf(
            '%s.%s',
            $hash, $salt
        );
    }

    /**
     * @param string $redirect_uri
     *
     * @return string
     */
    private function getOriginUri($redirect_uri)
    {
        $url_parts = parse_url($redirect_uri);

        return sprintf(
            '%s://%s%s',
            $url_parts['scheme'],
            $url_parts['host'],
            isset($url_parts['port']) ? ':'.$url_parts['port'] : ''
        );
    }
}
