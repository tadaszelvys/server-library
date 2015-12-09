<?php

/*
 * The MIT License (MIT)
 *
 * Copyright (c) 2014-2015 Spomky-Labs
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file for details.
 */

namespace OAuth2\Grant;

use OAuth2\Behaviour\HasIdTokenManager;
use OAuth2\Endpoint\Authorization;

final class IdTokenResponseType implements ResponseTypeSupportInterface
{
    use HasIdTokenManager;

    /**
     * {@inheritdoc}
     */
    public function getResponseType()
    {
        return 'id_token';
    }

    /**
     * {@inheritdoc}
     */
    public function getResponseMode()
    {
        return 'fragment';
    }

    /**
     * {@inheritdoc}
     */
    public function grantAuthorization(Authorization $authorization)
    {
        $id_token = $this->getIdTokenManager()->createIdToken($authorization->getClient(), $authorization->getEndUser(), $authorization->getScope());

        $params = [
            'id_token' => $id_token,
        ];
        $state = $authorization->getState();
        if (!empty($state)) {
            $params['state'] = $state;
        }

        return $params;
    }
}
