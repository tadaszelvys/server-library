<?php

/*
 * The MIT License (MIT)
 *
 * Copyright (c) 2014-2016 Spomky-Labs
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file for details.
 */

namespace OAuth2\Endpoint;

use OAuth2\Behaviour\HasExceptionManager;
use OAuth2\Exception\ExceptionManagerInterface;
use OAuth2\Exception\BaseExceptionInterface;
use OAuth2\Util\RequestBody;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;

/**
 * Class ClientRegistrationEndpoint
 */
class ClientRegistrationEndpoint implements ClientRegistrationEndpointInterface
{
    use HasExceptionManager;

    /**
     * ClientRegistrationEndpoint constructor.
     *
     * @param \OAuth2\Exception\ExceptionManagerInterface $exception_manager
     */
    public function __construct(ExceptionManagerInterface $exception_manager)
    {
        $this->setExceptionManager($exception_manager);
    }

    /**
     * {@inheritdoc}
     */
    public function register(ServerRequestInterface $request, ResponseInterface &$response)
    {
        try {

            //Check HTTPS
            if (!$this->isRequestSecured($request)) {
                throw $this->getExceptionManager()->getBadRequestException(ExceptionManagerInterface::INVALID_REQUEST, 'The request must be secured.');
            }

            //Check POST
            if ('POST' !== $request->getMethod()) {
                throw $this->getExceptionManager()->getBadRequestException(ExceptionManagerInterface::INVALID_REQUEST, 'Method must be POST.');
            }

            //Check Initial Access Token if required

            //Check application/json
            if (!in_array('application/json', $request->getHeader('content-type'))) {
                throw $this->getExceptionManager()->getBadRequestException(ExceptionManagerInterface::INVALID_REQUEST, 'Content Type must be a JSON object.');
            }

            //Get the content
            $content = RequestBody::getJsonObject($request);
            if (null === $content) {
                throw $this->getExceptionManager()->getBadRequestException(ExceptionManagerInterface::INVALID_REQUEST, 'Body contains an invalid JSON object.');
            }

            //Handle the request and populate the response accordingly
            $this->handleRequest($content, $response);
        } catch (BaseExceptionInterface $e) {
            $e->getHttpResponse($response);
        }
    }

    /**
     * @param array                               $content
     * @param \Psr\Http\Message\ResponseInterface $response
     */
    private function handleRequest(array $content, ResponseInterface &$response)
    {

    }

    /**
     * @param \Psr\Http\Message\ServerRequestInterface $request
     *
     * @return bool
     */
    private function isRequestSecured(ServerRequestInterface $request)
    {
        $server_params = $request->getServerParams();

        return !empty($server_params['HTTPS']) && 'on' === mb_strtolower($server_params['HTTPS'], '8bit');
    }
}
