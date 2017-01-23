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

use OAuth2\Command\CommandWithDataTransporter;
use OAuth2\DataTransporter;
use OAuth2\Model\UserAccount\UserAccountId;

final class CreateClientCommand extends CommandWithDataTransporter
{
    /**
     * @var array
     */
    private $parameters;

    /**
     * @var UserAccountId
     */
    private $userAccountId;

    /**
     * CreateClientCommand constructor.
     *
     * @param UserAccountId        $userAccountId
     * @param array                $parameters
     * @param DataTransporter|null $dataTransporter
     */
    protected function __construct(UserAccountId $userAccountId, array $parameters, DataTransporter $dataTransporter = null)
    {
        $this->parameters = $parameters;
        $this->userAccountId = $userAccountId;
        parent::__construct($dataTransporter);
    }

    /**
     * @param UserAccountId   $userAccountId
     * @param array           $parameters
     * @param DataTransporter $callback
     *
     * @return CreateClientCommand
     */
    public static function create(UserAccountId $userAccountId, array $parameters, DataTransporter $callback): self
    {
        return new self($userAccountId, $parameters, $callback);
    }

    /**
     * @return array
     */
    public function getParameters(): array
    {
        return $this->parameters;
    }

    /**
     * @return UserAccountId
     */
    public function getUserAccountId(): UserAccountId
    {
        return $this->userAccountId;
    }
}
