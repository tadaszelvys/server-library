<?php

declare(strict_types=1);

/*
 * The MIT License (MIT)
 *
 * Copyright (c) 2014-2016 Spomky-Labs
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file for details.
 */

namespace OAuth2\Response\Factory;

use OAuth2\Response\OAuth2ResponseInterface;
use Psr\Http\Message\ResponseInterface;

abstract class AuthenticateResponseFactory implements ResponseFactoryInterface
{
    /**
     * {@inheritdoc}
     */
    public function getSupportedCode(): int
    {
        return 401;
    }

    /**
     * {@inheritdoc}
     */
    public function createResponse(array $data, ResponseInterface &$response): OAuth2ResponseInterface
    {
        $schemes = $this->getSchemes();

        return new AuthenticateResponse(401, $data, $response, $schemes);
    }

    /**
     * @return array
     */
    abstract protected function getSchemes(): array;
}
