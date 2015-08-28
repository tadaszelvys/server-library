<?php

namespace OAuth2\Endpoint;

interface AuthorizationEndpointInterface
{
    /**
     * @param \OAuth2\Endpoint\AuthorizationInterface $authorization Authorization information
     *
     * @return \Symfony\Component\HttpFoundation\Response The response to send back to the client
     */
    public function authorize(AuthorizationInterface $authorization);
}
