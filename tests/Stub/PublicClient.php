<?php

namespace OAuth2\Test\Stub;

use OAuth2\Client\PublicClient as BasePublicClient;

class PublicClient extends BasePublicClient
{
    /**
     * {@inheritdoc}
     */
    public function getType()
    {
        return 'public_client';
    }
}
