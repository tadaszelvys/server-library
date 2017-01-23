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

namespace OAuth2\Event\Client;

use OAuth2\Model\Client\ClientId;
use OAuth2\Model\Event\Event;
use OAuth2\Model\UserAccount\UserAccountId;

final class ClientCreatedEvent extends Event
{
    /**
     * @var ClientId
     */
    private $clientId;

    /**
     * @var array
     */
    private $metadatas;

    /**
     * @var UserAccountId
     */
    private $userAccountId;

    /**
     * ClientCreatedEvent constructor.
     *
     * @param ClientId      $clientId
     * @param array         $metadatas
     * @param UserAccountId $userAccountId
     */
    protected function __construct(ClientId $clientId, array $metadatas, UserAccountId $userAccountId)
    {
        parent::__construct();
        $this->clientId = $clientId;
        $this->metadatas = $metadatas;
        $this->userAccountId = $userAccountId;
    }

    /**
     * @param ClientId      $clientId
     * @param array         $metadatas
     * @param UserAccountId $userAccountId
     *
     * @return self
     */
    public static function create(ClientId $clientId, array $metadatas, UserAccountId $userAccountId): self
    {
        return new self($clientId, $metadatas, $userAccountId);
    }

    /**
     * {@inheritdoc}
     */
    public function getPayload()
    {
        return [
            'client_id' => $this->clientId,
            'user_account_id' => $this->userAccountId,
            'metadatas' => $this->metadatas,
        ];
    }
}
