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
use OAuth2\GrantType\GrantTypeManagerInterface;
use OAuth2\ResponseType\ResponseTypeManagerInterface;
use OAuth2\Model\UserAccount\UserAccount;

final class GrantTypeFlowRule implements RuleInterface
{
    /**
     * @var GrantTypeManagerInterface
     */
    private $grant_type_manager;

    /**
     * @var ResponseTypeManagerInterface
     */
    private $response_type_manager;

    /**
     * GrantTypeFlowRule constructor.
     *
     * @param GrantTypeManagerInterface    $grant_type_manager
     * @param ResponseTypeManagerInterface $response_type_manager
     */
    public function __construct(GrantTypeManagerInterface $grant_type_manager, ResponseTypeManagerInterface $response_type_manager)
    {
        $this->grant_type_manager = $grant_type_manager;
        $this->response_type_manager = $response_type_manager;
    }

    /**
     * {@inheritdoc}
     */
    public function handle(array $command_parameters, array $validated_parameters, UserAccount $userAccount, callable $next)
    {
        if (!array_key_exists('grant_types', $command_parameters)) {
            $command_parameters['grant_types'] = [];
        }
        if (!array_key_exists('response_types', $command_parameters)) {
            $command_parameters['response_types'] = [];
        }
        $this->checkGrantTypes($command_parameters);
        $this->checkResponseTypes($command_parameters);

        $validated_parameters['grant_types'] = $command_parameters['grant_types'];
        $validated_parameters['response_types'] = $command_parameters['response_types'];

        return $next($command_parameters, $validated_parameters, $userAccount);
    }

    /**
     * @param array $parameters
     */
    private function checkGrantTypes(array $parameters)
    {
        Assertion::isArray($parameters['grant_types'], 'The parameter \'grant_types\' must be an array of strings.');
        Assertion::allString($parameters['grant_types'], 'The parameter \'grant_types\' must be an array of strings.');

        foreach ($parameters['grant_types'] as $grant_type) {
            $type = $this->grant_type_manager->getGrantType($grant_type);
            $associated_response_types = $type->getAssociatedResponseTypes();
            $diff = array_diff($associated_response_types, $parameters['response_types']);
            Assertion::true(empty($diff), sprintf('The grant type \'%s\' is associated with the response types \'%s\' but this response type is missing.', $type->getGrantType(), implode(', ', $diff)));
        }
    }

    /**
     * @param array $parameters
     */
    private function checkResponseTypes(array $parameters)
    {
        Assertion::isArray($parameters['response_types'], 'The parameter \'response_types\' must be an array of strings.');
        Assertion::allString($parameters['response_types'], 'The parameter \'response_types\' must be an array of strings.');

        foreach ($parameters['response_types'] as $response_type) {
            $types = $this->response_type_manager->getResponseTypes($response_type);
            foreach ($types as $type) {
                $associated_grant_types = $type->getAssociatedGrantTypes();
                $diff = array_diff($associated_grant_types, $parameters['grant_types']);
                Assertion::true(empty($diff), sprintf('The response type \'%s\' is associated with the grant types \'%s\' but this response type is missing.', $type->getResponseType(), implode(', ', $diff)));
            }
        }
    }
}
