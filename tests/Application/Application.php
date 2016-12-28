<?php

/*
 * The MIT License (MIT)
 *
 * Copyright (c) 2014-2016 Spomky-Labs
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file for details.
 */

namespace OAuth2\Test\Application;

final class Application
{
    use OAuth2ResponseFactoryTrait;
    use ClientRepositoryTrait;
    use ClientRegistrationEndpointTrait;
    use ClientEventHandlerTrait;
    use CommandBusTrait;
    use CommandHandlerMapTrait;
    use CommandHandlerResolverTrait;
    use ContainerTrait;
    use ClientCommandHandlerTrait;
    use EventBusTrait;
    use EventHandlerResolverTrait;
    use EventHandlerMapTrait;
    use PublicMessageRecorderTrait;
    use ResponseFactoryTrait;
    use RuleManagerTrait;
    use ServerRequestFactoryTrait;
    use ServiceLocatorAwareCallableResolverTrait;
    use ServiceLocatorTrait;
    use StreamFactoryTrait;
    use EventStoreTrait;
    use GrantTypeFlowRuleTrait;
    use GrantTypeManagerTrait;
    use ResponseTypeManagerTrait;
    use PKCEMethodTrait;
    use ScopeRepositoryTrait;
    use InitialAccessTokenTrait;
    use JwtTrait;
    use ClientConfigurationEndpointTrait;
}
