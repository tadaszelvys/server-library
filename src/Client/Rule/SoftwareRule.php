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
use Jose\JWTLoaderInterface;
use Jose\Object\JWKSetInterface;
use OAuth2\Model\UserAccount\UserAccountId;

final class SoftwareRule implements RuleInterface
{
    /**
     * @var null|JWTLoaderInterface
     */
    private $jwtLoader = null;

    /**
     * @var bool
     */
    private $isSoftwareStatementRequired = false;

    /**
     * @var null|JWKSetInterface
     */
    private $softwareStatementSignatureKeySet = null;

    /**
     * @return bool
     */
    public function isSoftwareStatementSupported(): bool
    {
        return null !== $this->softwareStatementSignatureKeySet;
    }

    /**
     * @return bool
     */
    public function isSoftwareStatementRequired(): bool
    {
        return $this->isSoftwareStatementRequired;
    }

    /**
     * @param JWTLoaderInterface $jwtLoader
     * @param JWKSetInterface $signature_key_set
     * @param bool $isSoftwareStatementRequired
     */
    public function enableSoftwareStatementSupport(JWTLoaderInterface $jwtLoader, JWKSetInterface $signature_key_set, bool $isSoftwareStatementRequired)
    {
        $this->jwtLoader = $jwtLoader;
        $this->softwareStatementSignatureKeySet = $signature_key_set;
        $this->isSoftwareStatementRequired = $isSoftwareStatementRequired;
    }

    /**
     * {@inheritdoc}
     */
    public function handle(array $commandParameters, array $validatedParameters, UserAccountId $userAccountId, callable $next)
    {
        Assertion::false($this->isSoftwareStatementRequired() && !array_key_exists('software_statement', $commandParameters), 'The parameter \'software_statement\' is mandatory.');
        if ($this->isSoftwareStatementSupported() && array_key_exists('software_statement', $commandParameters)) {
            $statement = $commandParameters['software_statement'];
            Assertion::string($statement, 'The software statement should be a string.');
            $software_statement = $this->loadSoftwareStatement($statement);
            $validatedParameters['software_statement'] = $commandParameters['software_statement'];
        } else {
            $software_statement = [];
        }

        foreach (['software_id', 'software_version'] as $key) {
            if (array_key_exists($key, $commandParameters)) {
                $validatedParameters[$key] = $commandParameters[$key];
            }
        }

        return array_merge(
            $next($commandParameters, $validatedParameters, $userAccountId),
            $software_statement
        );
    }

    /**
     * @param string $software_statement
     *
     * @return array
     */
    private function loadSoftwareStatement(string $software_statement): array
    {
        try {
            $jws = $this->jwtLoader->load($software_statement);
            $this->jwtLoader->verify($jws, $this->softwareStatementSignatureKeySet);

            return $jws->getClaims();
        } catch (\Exception $e) {
            throw new \InvalidArgumentException('Invalid Software Statement', $e->getCode(), $e);
        }
    }
}
