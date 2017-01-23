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

namespace OAuth2\Command\IdToken;

use OAuth2\Model\IdToken\IdTokenRepositoryInterface;

final class CreateIdTokenCommandHandler
{
    /**
     * @var IdTokenRepositoryInterface
     */
    private $idTokenRepository;

    /**
     * CreateClientCommandHandler constructor.
     *
     * @param IdTokenRepositoryInterface $idTokenRepository
     */
    public function __construct(IdTokenRepositoryInterface $idTokenRepository)
    {
        $this->idTokenRepository = $idTokenRepository;
    }

    /**
     * @param CreateIdTokenCommand $command
     */
    public function handle(CreateIdTokenCommand $command)
    {
        $idToken = $this->idTokenRepository->create(
            $command->getClient(),
            $command->getUserAccount(),
            $command->getRedirectUri(),
            $command->getParameters(),
            $command->getMetadatas(),
            $command->getScopes(),
            $command->getExpiresAt(),
            []
        );
        if (null !== $command->getDataTransporter()) {
            $data = $command->getDataTransporter();
            $data($idToken);
        }
    }
}
