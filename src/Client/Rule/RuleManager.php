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

final class RuleManager implements RuleManagerInterface
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
            $this->appendRule($rule);
        }
    }

    /**
     * Appends new middleware for this message bus. Should only be used at configuration time.
     *
     * @private
     *
     * @param RuleInterface $rule
     *
     * @return self
     */
    public function appendRule(RuleInterface $rule)
    {
        $this->rules[] = $rule;

        return $this;
    }

    /**
     * @return RuleInterface[]
     */
    public function getRules()
    {
        return $this->rules;
    }

    /**
     * {@inheritdoc}
     */
    public function handle(array $command_parameters, UserAccountId $userAccountId)
    {
        return call_user_func($this->callableForNextRule(0), $command_parameters, [], $userAccountId);
    }

    /**
     * @param int $index
     *
     * @return \Closure
     */
    private function callableForNextRule($index)
    {
        if (!isset($this->rules[$index])) {
            return function (array $command_parameters, array $validated_parameters, UserAccountId $userAccountId) {
                return $validated_parameters;
            };
        }
        $rule = $this->rules[$index];

        return function ($command_parameters, $validated_parameters, UserAccountId $userAccountId) use ($rule, $index) {
            return $rule->handle($command_parameters, $validated_parameters, $userAccountId, $this->callableForNextRule($index + 1));
        };
    }
}
