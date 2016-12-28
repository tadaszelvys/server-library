<?php

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
use Jose\JWTLoaderInterface;
use Jose\Object\JWKSetInterface;
use OAuth2\Model\UserAccount\UserAccount;

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
     * @var null|\Jose\Object\JWKSetInterface
     */
    private $softwareStatementSignatureKeySet = null;

    /**
     * {@inheritdoc}
     */
    public function isSoftwareStatementSupported(): bool
    {
        return null !== $this->softwareStatementSignatureKeySet;
    }

    /**
     * {@inheritdoc}
     */
    public function isSoftwareStatementRequired()
    {
        return $this->isSoftwareStatementRequired;
    }

    /**
     * {@inheritdoc}
     */
    public function enableSoftwareStatementSupport(JWTLoaderInterface $jwtLoader, JWKSetInterface $signature_key_set)
    {
        $this->jwtLoader = $jwtLoader;
        $this->softwareStatementSignatureKeySet = $signature_key_set;
    }

    public function allowRegistrationWithoutSoftwareStatement()
    {
        $this->isSoftwareStatementRequired = false;
    }

    public function disallowRegistrationWithoutSoftwareStatement()
    {
        Assertion::true($this->isSoftwareStatementSupported(), 'Software Statement not supported.');
        $this->isSoftwareStatementRequired = true;
    }

    /**
     * {@inheritdoc}
     */
    public function handle(array $command_parameters, array $validated_parameters, UserAccount $userAccount, callable $next)
    {
        Assertion::false($this->isSoftwareStatementRequired() && !array_key_exists('software_statement', $command_parameters), 'The parameter \'software_statement\' is mandatory.');
        if ($this->isSoftwareStatementSupported() && array_key_exists('software_statement', $command_parameters)) {
            $statement = $command_parameters['software_statement'];
            Assertion::string($statement, 'The software statement should be a string.');
            $software_statement = $this->loadSoftwareStatement($statement);
            $validated_parameters['software_statement'] = $command_parameters['software_statement'];
        } else {
            $software_statement = [];
        }

        foreach (['software_id', 'software_version'] as $key) {
            if (array_key_exists($key, $command_parameters)) {
                $validated_parameters[$key] = $command_parameters[$key];
            }
        }

        return array_merge(
            $next($command_parameters, $validated_parameters, $userAccount),
            $software_statement
        );
    }

    /**
     * @param string $software_statement
     *
     * @return array
     */
    private function loadSoftwareStatement($software_statement)
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
