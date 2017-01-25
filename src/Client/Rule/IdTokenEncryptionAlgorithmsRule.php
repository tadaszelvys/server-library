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

namespace OAuth2\Client\Rule;

use Assert\Assertion;
use OAuth2\Model\IdToken\IdTokenRepositoryInterface;
use OAuth2\Model\UserAccount\UserAccountId;

final class IdTokenEncryptionAlgorithmsRule implements RuleInterface
{
    /**
     * @var IdTokenRepositoryInterface
     */
    private $idTokenRepository;

    /**
     * IdTokenAlgorithmsRule constructor.
     *
     * @param IdTokenRepositoryInterface $idTokenRepository
     */
    public function __construct(IdTokenRepositoryInterface $idTokenRepository)
    {
        $this->idTokenRepository = $idTokenRepository;
    }

    /**
     * {@inheritdoc}
     */
    public function handle(array $commandParameters, array $validatedParameters, UserAccountId $userAccountId, callable $next)
    {
        if (array_key_exists('id_token_encrypted_response_alg', $commandParameters) && array_key_exists('id_token_encrypted_response_enc', $commandParameters)) {
            Assertion::string($commandParameters['id_token_encrypted_response_alg'], 'Invalid parameter \'id_token_encrypted_response_alg\'. The value must be a string.');
            Assertion::string($commandParameters['id_token_encrypted_response_enc'], 'Invalid parameter \'id_token_encrypted_response_enc\'. The value must be a string.');
            Assertion::inArray($commandParameters['id_token_encrypted_response_alg'], $this->idTokenRepository->getSupportedKeyEncryptionAlgorithms(), sprintf('The ID Token content encryption algorithm \'%s\' is not supported. Please choose one of the following algorithm: %s', $commandParameters['id_token_encrypted_response_alg'], implode(', ', $this->idTokenRepository->getSupportedContentEncryptionAlgorithms())));
            Assertion::inArray($commandParameters['id_token_encrypted_response_enc'], $this->idTokenRepository->getSupportedContentEncryptionAlgorithms(), sprintf('The ID Token key encryption algorithm \'%s\' is not supported. Please choose one of the following algorithm: %s', $commandParameters['id_token_encrypted_response_enc'], implode(', ', $this->idTokenRepository->getSupportedKeyEncryptionAlgorithms())));
            $validatedParameters['id_token_encrypted_response_alg'] = $commandParameters['id_token_encrypted_response_alg'];
            $validatedParameters['id_token_encrypted_response_enc'] = $commandParameters['id_token_encrypted_response_enc'];
        } elseif (array_key_exists('id_token_encrypted_response_alg', $commandParameters) || array_key_exists('id_token_encrypted_response_enc', $commandParameters)) {
            throw new \InvalidArgumentException('The parameters \'id_token_encrypted_response_alg\' and \'id_token_encrypted_response_enc\' must be set together');
        }

        return $next($commandParameters, $validatedParameters, $userAccountId);
    }
}
