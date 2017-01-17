<?php

declare(strict_types=1);

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
use OAuth2\OpenIdConnect\UserInfo\HasUserinfo;
use OAuth2\OpenIdConnect\UserInfo\UserInfoInterface;

final class SubjectTypeRule implements RuleInterface
{
    use HasUserinfo;

    /**
     * SubjectTypeRule constructor.
     *
     * @param \OAuth2\OpenIdConnect\UserInfo\UserInfoInterface $userinfo
     */
    public function __construct(UserInfoInterface $userinfo)
    {
        $this->setUserinfo($userinfo);
    }

    /**
     * {@inheritdoc}
     */
    public function handle(array $command_parameters, array $validated_parameters, UserAccount $userAccount, callable $next)
    {
        if (array_key_exists('subject_type', $command_parameters)) {
            Assertion::string($command_parameters['subject_type'], 'Invalid parameter \'subject_type\'. The value must be a string.');
            $supported_types = ['public'];
            if ($this->getUserinfo()->isPairwiseSubjectIdentifierSupported()) {
                $supported_types[] = 'pairwise';
            }

            Assertion::inArray($command_parameters['subject_type'], $supported_types, sprintf('The subject type \'%s\' is not supported. Please use one of the following value: %s', $command_parameters['subject_type'], implode(', ', $supported_types)));
            $validated_parameters['subject_type'] = $command_parameters['subject_type'];
        }

        return $next($command_parameters, $validated_parameters, $userAccount);
    }
}
