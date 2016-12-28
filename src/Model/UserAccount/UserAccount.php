<?php

/*
 * The MIT License (MIT)
 *
 * Copyright (c) 2014-2016 Spomky-Labs
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file for details.
 */

namespace OAuth2\Model\UserAccount;

use OAuth2\Model\ResourceOwner\ResourceOwner;

final class UserAccount extends ResourceOwner
{
    /**
     * @var UserAccountId
     */
    private $id;

    /**
     * UserAccount constructor.
     *
     * @param UserAccountId $id
     * @param array         $metadatas
     */
    protected function __construct(UserAccountId $id, array $metadatas)
    {
        parent::__construct($metadatas);
        $this->id = $id;
    }

    /**
     * @param UserAccountId $id
     * @param array         $metadatas
     *
     * @return self
     */
    public static function create(UserAccountId $id, array $metadatas): self
    {
        return new self($id, $metadatas);
    }

    /**
     * @return UserAccountId
     */
    public function getId(): UserAccountId
    {
        return $this->id;
    }
}
