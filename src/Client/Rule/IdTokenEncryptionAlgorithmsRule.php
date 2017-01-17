<?php declare(strict_types=1);

/*
 * The MIT License (MIT)
 *
 * Copyright (c) 2014-2016 Spomky-Labs
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file for details.
 */

namespace OAuth2\Client\Rule;

use Assert\Assertion;
use OAuth2\Model\UserAccount\UserAccount;
use OAuth2\OpenIdConnect\IdTokenManagerInterface;

final class IdTokenEncryptionAlgorithmsRule implements RuleInterface
{
    /**
     * @var IdTokenManagerInterface
     */
    private $id_token_manager;

    /**
     * IdTokenAlgorithmsRule constructor.
     *
     * @param \OAuth2\OpenIdConnect\IdTokenManagerInterface $id_token_manager
     */
    public function __construct(IdTokenManagerInterface $id_token_manager)
    {
        $this->id_token_manager = $id_token_manager;
    }

    /**
     * {@inheritdoc}
     */
    public function handle(array $command_parameters, array $validated_parameters, UserAccount $userAccount, callable $next)
    {
        if (array_key_exists('id_token_encrypted_response_alg', $command_parameters) && array_key_exists('id_token_encrypted_response_enc', $command_parameters)) {
            Assertion::string($command_parameters['id_token_encrypted_response_alg'], 'Invalid parameter \'id_token_encrypted_response_alg\'. The value must be a string.');
            Assertion::string($command_parameters['id_token_encrypted_response_enc'], 'Invalid parameter \'id_token_encrypted_response_enc\'. The value must be a string.');
            Assertion::inArray($command_parameters['id_token_encrypted_response_alg'], $this->id_token_manager->getSupportedKeyEncryptionAlgorithms(), sprintf('The ID Token content encryption algorithm \'%s\' is not supported. Please choose one of the following algorithm: %s', $command_parameters['id_token_encrypted_response_alg'], implode(', ', $this->id_token_manager->getSupportedContentEncryptionAlgorithms())));
            Assertion::inArray($command_parameters['id_token_encrypted_response_enc'], $this->id_token_manager->getSupportedContentEncryptionAlgorithms(), sprintf('The ID Token key encryption algorithm \'%s\' is not supported. Please choose one of the following algorithm: %s', $command_parameters['id_token_encrypted_response_enc'], implode(', ', $this->id_token_manager->getSupportedKeyEncryptionAlgorithms())));
            $validated_parameters['id_token_encrypted_response_alg'] = $command_parameters['id_token_encrypted_response_alg'];
            $validated_parameters['id_token_encrypted_response_enc'] = $command_parameters['id_token_encrypted_response_enc'];
        } elseif (array_key_exists('id_token_encrypted_response_alg', $command_parameters) || array_key_exists('id_token_encrypted_response_enc', $command_parameters)) {
            throw new \InvalidArgumentException('The parameters \'id_token_encrypted_response_alg\' and \'id_token_encrypted_response_enc\' must be set together');
        }

        return $next($command_parameters, $validated_parameters, $userAccount);
    }
}
