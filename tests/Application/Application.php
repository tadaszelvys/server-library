<?php

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
