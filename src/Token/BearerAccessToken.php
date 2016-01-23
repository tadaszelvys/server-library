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

class BearerAccessToken implements TokenTypeInterface
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
}
