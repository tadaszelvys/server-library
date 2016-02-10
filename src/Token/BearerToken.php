<?php

/*
 * The MIT License (MIT)
 *
 * Copyright (c) 2014-2016 Spomky-Labs
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file for details.
 */

namespace OAuth2\Token;

use Psr\Http\Message\ServerRequestInterface;

class BearerToken implements TokenTypeInterface
{
    /**
     * {@inheritdoc}
     */
    public function getTokenTypeName()
    {
        return 'Bearer';
    }

    /**
     * {@inheritdoc}
     */
    public function getTokenTypeInformation()
    {
        return [
            'token_type' => $this->getTokenTypeName(),
        ];
    }

    /**
     * {@inheritdoc}
     */
    public function findToken(ServerRequestInterface $request)
    {
        $header = $request->getHeader('AUTHORIZATION');

        if (0 === count($header)) {
            return;
        }

        if (!preg_match('/'.preg_quote('Bearer', '/').'\s([a-zA-Z0-9\-_\+~\/\.]+)/', $header[0], $matches)) {
            return;
        }

        return $matches[1];
    }

    /**
     * {@inheritdoc}
     */
    public function isTokenRequestValid(AccessTokenInterface $access_token, ServerRequestInterface $request)
    {
        if ($access_token->getTokenType() !== $this->getTokenTypeName()) {
            return false;
        }
        return true;
    }
}
