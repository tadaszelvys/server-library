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
use OAuth2\Endpoint\UserInfo\UserInfoInterface;
use OAuth2\Model\UserAccount\UserAccountId;

final class SubjectTypeRule implements RuleInterface
{
    /**
     * @var UserInfoInterface
     */
    private $userinfo;

    /**
     * SubjectTypeRule constructor.
     *
     * @param UserInfoInterface $userinfo
     */
    public function __construct(UserInfoInterface $userinfo)
    {
        $this->userinfo = $userinfo;
    }

    /**
     * {@inheritdoc}
     */
    public function handle(array $commandParameters, array $validatedParameters, UserAccountId $userAccountId, callable $next)
    {
        if (array_key_exists('subject_type', $commandParameters)) {
            Assertion::string($commandParameters['subject_type'], 'Invalid parameter \'subject_type\'. The value must be a string.');
            $supported_types = ['public'];
            if ($this->userinfo->isPairwiseSubjectIdentifierSupported()) {
                $supported_types[] = 'pairwise';
            }

            Assertion::inArray($commandParameters['subject_type'], $supported_types, sprintf('The subject type \'%s\' is not supported. Please use one of the following value: %s', $commandParameters['subject_type'], implode(', ', $supported_types)));
            $validatedParameters['subject_type'] = $commandParameters['subject_type'];
        }

        return $next($commandParameters, $validatedParameters, $userAccountId);
    }
}
