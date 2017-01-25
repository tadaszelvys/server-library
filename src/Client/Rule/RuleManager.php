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

use OAuth2\Model\UserAccount\UserAccountId;

final class RuleManager
{
    /**
     * @var RuleInterface[]
     */
    private $rules = [];

    /**
     * RuleManager constructor.
     *
     * @param RuleInterface[] $rules
     */
    public function __construct(array $rules = [])
    {
        foreach ($rules as $rule) {
            $this->add($rule);
        }
    }

    /**
     * Appends new middleware for this message bus. Should only be used at configuration time.
     *
     * @param RuleInterface $rule
     *
     * @return RuleManager
     */
    public function add(RuleInterface $rule): RuleManager
    {
        $this->rules[] = $rule;

        return $this;
    }

    /**
     * @return RuleInterface[]
     */
    public function all(): array
    {
        return $this->rules;
    }

    /**
     * @param array         $commandParameters
     * @param UserAccountId $userAccountId
     *
     * @return array
     */
    public function handle(array $commandParameters, UserAccountId $userAccountId): array
    {
        return call_user_func($this->callableForNextRule(0), $commandParameters, [], $userAccountId);
    }

    /**
     * @param int $index
     *
     * @return \Closure
     */
    private function callableForNextRule(int $index): \Closure
    {
        if (!isset($this->rules[$index])) {
            return function (array $commandParameters, array $validatedParameters, UserAccountId $userAccountId) {
                return $validatedParameters;
            };
        }
        $rule = $this->rules[$index];

        return function (array $commandParameters, array $validatedParameters, UserAccountId $userAccountId) use ($rule, $index) {
            return $rule->handle($commandParameters, $validatedParameters, $userAccountId, $this->callableForNextRule($index + 1));
        };
    }
}
