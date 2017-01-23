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

namespace OAuth2\Command\Client;

use OAuth2\Model\Client\ClientId;

final class DeleteClientCommand
{
    /**
     * @var ClientId
     */
    private $clientId;

    /**
     * DeleteClientCommand constructor.
     *
     * @param ClientId $clientId
     */
    protected function __construct(ClientId $clientId)
    {
        $this->clientId = $clientId;
    }

    /**
     * @param ClientId $clientId
     *
     * @return DeleteClientCommand
     */
    public static function create(ClientId $clientId): DeleteClientCommand
    {
        return new self($clientId);
    }

    /**
     * @return ClientId
     */
    public function getClientId(): ClientId
    {
        return $this->clientId;
    }
}
