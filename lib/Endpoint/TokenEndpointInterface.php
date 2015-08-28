<?php

namespace OAuth2\Endpoint;

use Symfony\Component\HttpFoundation\Request;

interface TokenEndpointInterface
{
    /**
     * @param \Symfony\Component\HttpFoundation\Request $request The request
     *
     * @return \Symfony\Component\HttpFoundation\Response
     *
     * @throws \OAuth2\Exception\BaseExceptionInterface If an error occurred
     */
    public function getAccessToken(Request $request);
}
