<?php declare(strict_types=1);

/*
 * The MIT License (MIT)
 *
 * Copyright (c) 2014-2016 Spomky-Labs
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file for details.
 */

namespace OAuth2\Command\Client;

use OAuth2\Command\CommandWithDataTransporter;
use OAuth2\DataTransporter;
use OAuth2\Model\UserAccount\UserAccount;

final class CreateClientCommand extends CommandWithDataTransporter
{
    /**
     * @var array
     */
    private $parameters;

    /**
     * @var UserAccount
     */
    private $userAccount;

    /**
     * CreateClientCommand constructor.
     * @param UserAccount $userAccount
     * @param array $parameters
     * @param DataTransporter|null $dataTransporter
     */
    protected function __construct(UserAccount $userAccount, array $parameters, DataTransporter $dataTransporter = null)
    {
        $this->parameters = $parameters;
        $this->userAccount = $userAccount;
        parent::__construct($dataTransporter);
    }

    /**
     * @param UserAccount     $userAccount
     * @param array           $parameters
     * @param DataTransporter $callback
     *
     * @return CreateClientCommand
     */
    public static function create(UserAccount $userAccount, array $parameters, DataTransporter $callback): self
    {
        return new self($userAccount, $parameters, $callback);
    }

    /**
     * @return array
     */
    public function getParameters(): array
    {
        return $this->parameters;
    }

    /**
     * @return UserAccount
     */
    public function getUserAccount(): UserAccount
    {
        return $this->userAccount;
    }
}
