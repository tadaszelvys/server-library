<?php

namespace OAuth2\Endpoint;

use Psr\Http\Message\ResponseInterface;

interface ResponseModeInterface
{
    /**
     * @return string
     */
    public function getName();

    /**
     * @param string                              $redirect_uri
     * @param array                               $data
     * @param \Psr\Http\Message\ResponseInterface $response
     */
    public function prepareResponse($redirect_uri, array $data, ResponseInterface &$response);
}
