<?php

declare(strict_types=1);

/*
 * The MIT License (MIT)
 *
 * Copyright (c) 2014-2017 Spomky-Labs
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file for details.
 */

namespace OAuth2\Endpoint\TokenRevocation;

use Interop\Http\Factory\ResponseFactoryInterface;
use OAuth2\TokenTypeHint\TokenTypeHintManagerInterface;
use Psr\Http\Message\ServerRequestInterface;
use Webmozart\Json\JsonEncoder;

final class TokenRevocationGetEndpoint extends TokenRevocationEndpoint
{
    /**
     * @var bool
     */
    private $allowJson;

    /**
     * TokenRevocationGetEndpoint constructor.
     *
     * @param TokenTypeHintManagerInterface $tokenTypeHintManager
     * @param ResponseFactoryInterface      $responseFactory
     * @param JsonEncoder                   $encoder
     * @param bool                          $allowJson
     */
    public function __construct(TokenTypeHintManagerInterface $tokenTypeHintManager, ResponseFactoryInterface $responseFactory, JsonEncoder $encoder, bool $allowJson)
    {
        parent::__construct($tokenTypeHintManager, $responseFactory, $encoder);
        $this->allowJson = $allowJson;
    }

    /**
     * {@inheritdoc}
     */
    protected function getRequestParameters(ServerRequestInterface $request): array
    {
        $parameters = $request->getQueryParams();
        $supported_parameters = ['token', 'token_type_hint'];
        if (true === $this->allowJson) {
            $supported_parameters[] = 'callback';
        }

        return array_intersect_key($parameters, array_flip($supported_parameters));
    }
}
