<?php

/*
 * The MIT License (MIT)
 *
 * Copyright (c) 2014-2016 Spomky-Labs
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file for details.
 */

namespace OAuth2\Endpoint\TokenRevocation;

use OAuth2\TokenTypeHint\TokenTypeHintManagerInterface;
use Psr\Http\Message\ServerRequestInterface;

final class TokenRevocationGetEndpoint extends TokenRevocationEndpoint
{
    /**
     * @var bool
     */
    private $allowJson;

    /**
     * TokenRevocationGetEndpoint constructor.
     * @param TokenTypeHintManagerInterface $tokenTypeHintManager
     * @param bool $allowJson
     */
    public function __construct(TokenTypeHintManagerInterface $tokenTypeHintManager, bool $allowJson)
    {
        parent::__construct($tokenTypeHintManager);
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
