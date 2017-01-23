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

namespace OAuth2\Test\Application;

use Http\Factory\Diactoros\ResponseFactory;
use Http\Factory\Diactoros\ServerRequestFactory;
use Http\Factory\Diactoros\StreamFactory;
use Interop\Http\Factory\ResponseFactoryInterface;
use Interop\Http\Factory\ServerRequestFactoryInterface;
use Interop\Http\Factory\StreamFactoryInterface;
use Jose\Checker\CheckerManager;
use Jose\Decrypter;
use Jose\Encrypter;
use Jose\Factory\JWKFactory;
use Jose\JWTCreator;
use Jose\JWTLoader;
use Jose\Object\JWKSetInterface;
use Jose\Signer;
use Jose\Verifier;
use OAuth2\Client\Rule\ClientIdRule;
use OAuth2\Client\Rule\CommonParametersRule;
use OAuth2\Client\Rule\GrantTypeFlowRule;
use OAuth2\Client\Rule\RedirectionUriRule;
use OAuth2\Client\Rule\RuleManager;
use OAuth2\Client\Rule\ScopeRule;
use OAuth2\Client\Rule\SoftwareRule;
use OAuth2\Command\AccessToken\CreateAccessTokenCommand;
use OAuth2\Command\AccessToken\CreateAccessTokenCommandHandler;
use OAuth2\Command\AccessToken\RevokeAccessTokenCommand;
use OAuth2\Command\AccessToken\RevokeAccessTokenCommandHandler;
use OAuth2\Command\Client\CreateClientCommand;
use OAuth2\Command\Client\CreateClientCommandHandler;
use OAuth2\Command\Client\DeleteClientCommand;
use OAuth2\Command\Client\DeleteClientCommandHandler;
use OAuth2\Command\Client\UpdateClientCommand;
use OAuth2\Command\Client\UpdateClientCommandHandler;
use OAuth2\Command\RefreshToken\RevokeRefreshTokenCommand;
use OAuth2\Command\RefreshToken\RevokeRefreshTokenCommandHandler;
use OAuth2\Endpoint\ClientConfiguration\ClientConfigurationEndpoint;
use OAuth2\Endpoint\ClientRegistration\ClientRegistrationEndpoint;
use OAuth2\Endpoint\Token\TokenEndpoint;
use OAuth2\Endpoint\TokenIntrospection\TokenIntrospectionEndpoint;
use OAuth2\Endpoint\TokenRevocation\TokenRevocationGetEndpoint;
use OAuth2\Endpoint\TokenRevocation\TokenRevocationPostEndpoint;
use OAuth2\Event\AccessToken\AccessTokenCreatedEvent;
use OAuth2\Event\AccessToken\AccessTokenRevokedEvent;
use OAuth2\Event\Client\ClientCreatedEvent;
use OAuth2\Event\Client\ClientDeletedEvent;
use OAuth2\Event\Client\ClientUpdatedEvent;
use OAuth2\Event\RefreshToken\RefreshTokenCreatedEvent;
use OAuth2\Event\RefreshToken\RefreshTokenRevokedEvent;
use OAuth2\GrantType\ClientCredentialsGrantType;
use OAuth2\GrantType\GrantTypeManager;
use OAuth2\GrantType\GrantTypeManagerInterface;
use OAuth2\GrantType\JWTBearerGrantType;
use OAuth2\GrantType\PKCEMethod\PKCEMethodInterface;
use OAuth2\GrantType\PKCEMethod\PKCEMethodManager;
use OAuth2\GrantType\PKCEMethod\PKCEMethodManagerInterface;
use OAuth2\GrantType\PKCEMethod\Plain;
use OAuth2\GrantType\PKCEMethod\S256;
use OAuth2\GrantType\RefreshTokenGrantType;
use OAuth2\GrantType\ResourceOwnerPasswordCredentialsGrantType;
use OAuth2\Middleware\ClientAuthenticationMiddleware;
use OAuth2\Middleware\GrantTypeMiddleware;
use OAuth2\Middleware\HttpMethod;
use OAuth2\Middleware\InitialAccessTokenMiddleware;
use OAuth2\Middleware\Pipe;
use OAuth2\Middleware\TokenTypeMiddleware;
use OAuth2\Model\AccessToken\AccessTokenRepositoryInterface;
use OAuth2\Model\AuthCode\AuthCodeRepositoryInterface;
use OAuth2\Model\Event\EventStoreInterface;
use OAuth2\Model\InitialAccessToken\InitialAccessTokenRepositoryInterface;
use OAuth2\Model\RefreshToken\RefreshTokenRepositoryInterface;
use OAuth2\Model\Scope\DefaultScopePolicy;
use OAuth2\Model\Scope\ErrorScopePolicy;
use OAuth2\Model\Scope\ScopePolicyInterface;
use OAuth2\Model\Scope\ScopeRepository;
use OAuth2\Model\Scope\ScopeRepositoryInterface;
use OAuth2\Model\UserAccount\UserAccountRepositoryInterface;
use OAuth2\Response\Factory\AccessDeniedResponseFactory;
use OAuth2\Response\Factory\BadRequestResponseFactory;
use OAuth2\Response\Factory\MethodNotAllowedResponseFactory;
use OAuth2\Response\Factory\NotImplementedResponseFactory;
use OAuth2\Response\OAuth2ExceptionMiddleware;
use OAuth2\Response\OAuth2ResponseFactoryManager;
use OAuth2\Response\OAuth2ResponseFactoryManagerInterface;
use OAuth2\ResponseType\CodeResponseType;
use OAuth2\ResponseType\ImplicitResponseType;
use OAuth2\ResponseType\ResponseTypeManager;
use OAuth2\ResponseType\ResponseTypeManagerInterface;
use OAuth2\Test\Stub\AccessTokenRepository;
use OAuth2\Test\Stub\AuthCodeRepository;
use OAuth2\Test\Stub\AuthenticateResponseFactory;
use OAuth2\Test\Stub\ClientAssertionJwt;
use OAuth2\Test\Stub\ClientRegistrationManagementRule;
use OAuth2\Test\Stub\ClientRepository;
use OAuth2\Test\Stub\ClientSecretBasic;
use OAuth2\Test\Stub\ClientSecretPost;
use OAuth2\Test\Stub\Container;
use OAuth2\Test\Stub\Event\AccessTokenCreatedEventHandler;
use OAuth2\Test\Stub\Event\AccessTokenRevokedEventHandler;
use OAuth2\Test\Stub\Event\ClientCreatedEventHandler;
use OAuth2\Test\Stub\Event\ClientDeletedEventHandler;
use OAuth2\Test\Stub\Event\ClientUpdatedEventHandler;
use OAuth2\Test\Stub\Event\RefreshTokenCreatedEventHandler;
use OAuth2\Test\Stub\Event\RefreshTokenRevokedEventHandler;
use OAuth2\Test\Stub\EventStore;
use OAuth2\Test\Stub\InitialAccessTokenRepository;
use OAuth2\Test\Stub\MacToken;
use OAuth2\Test\Stub\RefreshTokenRepository;
use OAuth2\Test\Stub\ServiceLocator;
use OAuth2\Test\Stub\UriExtension;
use OAuth2\Test\Stub\UserAccountRepository;
use OAuth2\TokenEndpointAuthMethod\None;
use OAuth2\TokenEndpointAuthMethod\TokenEndpointAuthMethodManager;
use OAuth2\TokenType\BearerToken;
use OAuth2\TokenType\TokenTypeManager;
use OAuth2\TokenType\TokenTypeManagerInterface;
use OAuth2\TokenTypeHint\AccessTokenTypeHint;
use OAuth2\TokenTypeHint\AuthCodeTypeHint;
use OAuth2\TokenTypeHint\RefreshTokenTypeHint;
use OAuth2\TokenTypeHint\TokenTypeHintManager;
use OAuth2\TokenTypeHint\TokenTypeHintManagerInterface;
use SimpleBus\Message\Bus\Middleware\FinishesHandlingMessageBeforeHandlingNext;
use SimpleBus\Message\Bus\Middleware\MessageBusSupportingMiddleware;
use SimpleBus\Message\CallableResolver\CallableCollection;
use SimpleBus\Message\CallableResolver\CallableMap;
use SimpleBus\Message\CallableResolver\ServiceLocatorAwareCallableResolver;
use SimpleBus\Message\Handler\DelegatesToMessageHandlerMiddleware;
use SimpleBus\Message\Handler\Resolver\NameBasedMessageHandlerResolver;
use SimpleBus\Message\Name\ClassBasedNameResolver;
use SimpleBus\Message\Recorder\HandlesRecordedMessagesMiddleware;
use SimpleBus\Message\Recorder\PublicMessageRecorder;
use SimpleBus\Message\Subscriber\NotifiesMessageSubscribersMiddleware;
use SimpleBus\Message\Subscriber\Resolver\NameBasedMessageSubscriberResolver;
use Webmozart\Json\JsonDecoder;
use Webmozart\Json\JsonEncoder;

final class Application
{
    /**
     * @var null|OAuth2ResponseFactoryManagerInterface
     */
    private $oauth2ResponseFactory = null;

    /**
     * @var null|OAuth2ExceptionMiddleware
     */
    private $oauth2ResponseMiddleware = null;

    /**
     * @return OAuth2ResponseFactoryManagerInterface
     */
    public function getOAuth2ResponseFactory(): OAuth2ResponseFactoryManagerInterface
    {
        if (null === $this->oauth2ResponseFactory) {
            $this->oauth2ResponseFactory = new OAuth2ResponseFactoryManager(
                $this->getResponseFactory(),
                $this->getStreamFactory()
            );
            $this->oauth2ResponseFactory->addExtension(new UriExtension());

            $this->oauth2ResponseFactory->addResponseFactory(new AuthenticateResponseFactory(
                $this->getTokenEndpointAuthMethodManager()
            ));
            $this->oauth2ResponseFactory->addResponseFactory(new AccessDeniedResponseFactory());
            $this->oauth2ResponseFactory->addResponseFactory(new BadRequestResponseFactory());
            $this->oauth2ResponseFactory->addResponseFactory(new MethodNotAllowedResponseFactory());
            $this->oauth2ResponseFactory->addResponseFactory(new NotImplementedResponseFactory());
        }

        return $this->oauth2ResponseFactory;
    }

    /**
     * @return OAuth2ExceptionMiddleware
     */
    public function getOAuth2ResponseMiddleware(): OAuth2ExceptionMiddleware
    {
        if (null === $this->oauth2ResponseMiddleware) {
            $this->oauth2ResponseMiddleware = new OAuth2ExceptionMiddleware(
                $this->getOAuth2ResponseFactory()
            );
        }

        return $this->oauth2ResponseMiddleware;
    }

    /**
     * @var null|ClientRepository
     */
    private $clientRepository = null;

    /**
     * @return ClientRepository
     */
    public function getClientRepository(): ClientRepository
    {
        if (null === $this->clientRepository) {
            $this->clientRepository = new ClientRepository();
        }

        return $this->clientRepository;
    }

    /**
     * @var null|ClientRegistrationEndpoint
     */
    private $clientRegistrationEndpoint = null;

    /**
     * @return ClientRegistrationEndpoint
     */
    public function getClientRegistrationEndpoint(): ClientRegistrationEndpoint
    {
        if (null === $this->clientRegistrationEndpoint) {
            $this->clientRegistrationEndpoint = new ClientRegistrationEndpoint(
                $this->getResponseFactory(),
                $this->getCommandBus(),
                $this->getJsonEncoder()
            );
        }

        return $this->clientRegistrationEndpoint;
    }

    /**
     * @var null|Pipe
     */
    private $clientRegistrationPipe = null;

    /**
     * @return Pipe
     */
    public function getClientRegistrationPipe(): Pipe
    {
        if (null === $this->clientRegistrationPipe) {
            $this->clientRegistrationPipe = new Pipe();

            $this->clientRegistrationPipe->appendMiddleware($this->getOAuth2ResponseMiddleware());
            $this->clientRegistrationPipe->appendMiddleware($this->getInitialAccessTokenMiddleware());
            $this->clientRegistrationPipe->appendMiddleware($this->getClientRegistrationEndpoint());
        }

        return $this->clientRegistrationPipe;
    }

    /**
     * @var null|ClientAuthenticationMiddleware
     */
    private $clientAuthenticationMiddleware = null;

    /**
     * @return ClientAuthenticationMiddleware
     */
    public function getClientAuthenticationMiddleware(): ClientAuthenticationMiddleware
    {
        if (null === $this->clientAuthenticationMiddleware) {
            $this->clientAuthenticationMiddleware = new ClientAuthenticationMiddleware(
                $this->getTokenEndpointAuthMethodManager(),
                false
            );
        }

        return $this->clientAuthenticationMiddleware;
    }

    /**
     * @var null|ClientAuthenticationMiddleware
     */
    private $clientAuthenticationMiddlewareWithRequirement = null;

    /**
     * @return ClientAuthenticationMiddleware
     */
    public function getClientAuthenticationMiddlewareWithRequirement(): ClientAuthenticationMiddleware
    {
        if (null === $this->clientAuthenticationMiddlewareWithRequirement) {
            $this->clientAuthenticationMiddlewareWithRequirement = new ClientAuthenticationMiddleware(
                $this->getTokenEndpointAuthMethodManager(),
                true
            );
        }

        return $this->clientAuthenticationMiddlewareWithRequirement;
    }

    /**
     * @var null|TokenEndpointAuthMethodManager
     */
    private $tokenEndpointAuthMethodManager = null;

    /**
     * @return TokenEndpointAuthMethodManager
     */
    public function getTokenEndpointAuthMethodManager(): TokenEndpointAuthMethodManager
    {
        if (null === $this->tokenEndpointAuthMethodManager) {
            $this->tokenEndpointAuthMethodManager = new TokenEndpointAuthMethodManager(
                $this->getClientRepository()
            );
            $this->tokenEndpointAuthMethodManager->addTokenEndpointAuthMethod(new None());
            $this->tokenEndpointAuthMethodManager->addTokenEndpointAuthMethod(new ClientSecretBasic('My service'));
            $this->tokenEndpointAuthMethodManager->addTokenEndpointAuthMethod(new ClientSecretPost());
            $this->tokenEndpointAuthMethodManager->addTokenEndpointAuthMethod(new ClientAssertionJwt(
                $this->getJwtLoader()
            ));
        }

        return $this->tokenEndpointAuthMethodManager;
    }

    /**
     * @var null|ClientCreatedEventHandler
     */
    private $clientCreatedEventHandler = null;

    /**
     * @return ClientCreatedEventHandler
     */
    public function getClientCreatedEventHandler(): ClientCreatedEventHandler
    {
        if (null === $this->clientCreatedEventHandler) {
            $this->clientCreatedEventHandler = new ClientCreatedEventHandler();
        }

        return $this->clientCreatedEventHandler;
    }

    /**
     * @var null|ClientDeletedEventHandler
     */
    private $clientDeletedEventHandler = null;

    /**
     * @return ClientDeletedEventHandler
     */
    public function getClientDeletedEventHandler(): ClientDeletedEventHandler
    {
        if (null === $this->clientDeletedEventHandler) {
            $this->clientDeletedEventHandler = new ClientDeletedEventHandler();
        }

        return $this->clientDeletedEventHandler;
    }

    /**
     * @var null|ClientUpdatedEventHandler
     */
    private $clientUpdatedEventHandler = null;

    /**
     * @return ClientUpdatedEventHandler
     */
    public function getClientUpdatedEventHandler(): ClientUpdatedEventHandler
    {
        if (null === $this->clientUpdatedEventHandler) {
            $this->clientUpdatedEventHandler = new ClientUpdatedEventHandler();
        }

        return $this->clientUpdatedEventHandler;
    }

    /**
     * @var null|MessageBusSupportingMiddleware
     */
    private $commandBus = null;

    /**
     * @return MessageBusSupportingMiddleware
     */
    public function getCommandBus(): MessageBusSupportingMiddleware
    {
        if (null === $this->commandBus) {
            $this->commandBus = new MessageBusSupportingMiddleware();
            $this->commandBus->appendMiddleware(new HandlesRecordedMessagesMiddleware(
                $this->getPublicMessageRecorder(),
                $this->getEventBus()
            ));
            $this->commandBus->appendMiddleware(new FinishesHandlingMessageBeforeHandlingNext());
            $this->commandBus->appendMiddleware(new DelegatesToMessageHandlerMiddleware(
                $this->getCommandHandlerResolver()
            ));
        }

        return $this->commandBus;
    }

    /**
     * @var null|CallableMap
     */
    private $commandHandlerMap = null;

    /**
     * @return CallableMap
     */
    public function getCommandHandlerMap(): CallableMap
    {
        if (null === $this->commandHandlerMap) {
            $this->commandHandlerMap = new CallableMap(
                [
                    CreateClientCommand::class       => CreateClientCommandHandler::class,
                    DeleteClientCommand::class       => DeleteClientCommandHandler::class,
                    UpdateClientCommand::class       => UpdateClientCommandHandler::class,
                    CreateAccessTokenCommand::class  => CreateAccessTokenCommandHandler::class,
                    RevokeAccessTokenCommand::class  => RevokeAccessTokenCommandHandler::class,
                    RevokeRefreshTokenCommand::class => RevokeRefreshTokenCommandHandler::class,
                ],
                $this->getServiceLocatorAwareCallableResolver()
            );
        }

        return $this->commandHandlerMap;
    }

    /**
     * @var null|NameBasedMessageHandlerResolver
     */
    private $commandHandlerResolver = null;

    /**
     * @return NameBasedMessageHandlerResolver
     */
    public function getCommandHandlerResolver(): NameBasedMessageHandlerResolver
    {
        if (null === $this->commandHandlerResolver) {
            $this->commandHandlerResolver = new NameBasedMessageHandlerResolver(
                new ClassBasedNameResolver(),
                $this->getCommandHandlerMap()
            );
        }

        return $this->commandHandlerResolver;
    }

    /**
     * @var null|Container
     */
    private $container = null;

    /**
     * @return Container
     */
    public function getContainer(): Container
    {
        if (null === $this->container) {
            $this->container = new Container();

            $this->container->add($this->getCreateClientCommandHandler());
            $this->container->add($this->getDeleteClientCommandHandler());
            $this->container->add($this->getUpdateClientCommandHandler());

            $this->container->add($this->getClientCreatedEventHandler());
            $this->container->add($this->getClientDeletedEventHandler());
            $this->container->add($this->getClientUpdatedEventHandler());

            $this->container->add($this->getRevokeAccessTokenCommandHandler());
            $this->container->add($this->getAccessTokenRevokedEventHandler());

            $this->container->add($this->getCreateAccessTokenCommandHandler());
            $this->container->add($this->getAccessTokenCreatedEventHandler());

            $this->container->add($this->getRevokeRefreshTokenCommandHandler());
            $this->container->add($this->getRefreshTokenRevokedEventHandler());
        }

        return $this->container;
    }

    /**
     * @var null|CreateClientCommandHandler
     */
    private $createClientCommandHandler = null;

    /**
     * @return CreateClientCommandHandler
     */
    public function getCreateClientCommandHandler(): CreateClientCommandHandler
    {
        if (null === $this->createClientCommandHandler) {
            $this->createClientCommandHandler = new CreateClientCommandHandler(
                $this->getClientRepository(),
                $this->getRuleManager(),
                $this->getPublicMessageRecorder()
            );
        }

        return $this->createClientCommandHandler;
    }

    /**
     * @var null|DeleteClientCommandHandler
     */
    private $deleteClientCommandHandler = null;

    /**
     * @return DeleteClientCommandHandler
     */
    public function getDeleteClientCommandHandler(): DeleteClientCommandHandler
    {
        if (null === $this->deleteClientCommandHandler) {
            $this->deleteClientCommandHandler = new DeleteClientCommandHandler(
                $this->getClientRepository(),
                $this->getPublicMessageRecorder()
            );
        }

        return $this->deleteClientCommandHandler;
    }

    /**
     * @var null|UpdateClientCommandHandler
     */
    private $updateClientCommandHandler = null;

    /**
     * @return UpdateClientCommandHandler
     */
    public function getUpdateClientCommandHandler(): UpdateClientCommandHandler
    {
        if (null === $this->updateClientCommandHandler) {
            $this->updateClientCommandHandler = new UpdateClientCommandHandler(
                $this->getClientRepository(),
                $this->getRuleManager(),
                $this->getPublicMessageRecorder()
            );
        }

        return $this->updateClientCommandHandler;
    }

    /**
     * @var null|MessageBusSupportingMiddleware
     */
    private $eventBus = null;

    /**
     * @return MessageBusSupportingMiddleware
     */
    public function getEventBus(): MessageBusSupportingMiddleware
    {
        if (null === $this->eventBus) {
            $this->eventBus = new MessageBusSupportingMiddleware();
            $this->eventBus->appendMiddleware(new FinishesHandlingMessageBeforeHandlingNext());
            $this->eventBus->appendMiddleware(new NotifiesMessageSubscribersMiddleware(
                $this->getEventHandlerResolver()
            ));
        }

        return $this->eventBus;
    }

    /**
     * @var null|NameBasedMessageSubscriberResolver
     */
    private $eventHandlerResolver = null;

    /**
     * @return NameBasedMessageSubscriberResolver
     */
    public function getEventHandlerResolver(): NameBasedMessageSubscriberResolver
    {
        if (null === $this->eventHandlerResolver) {
            $this->eventHandlerResolver = new NameBasedMessageSubscriberResolver(
                new ClassBasedNameResolver(),
                $this->getEventHandlerMap()
            );
        }

        return $this->eventHandlerResolver;
    }

    /**
     * @var null|CallableCollection
     */
    private $eventHandlerMap = null;

    /**
     * @return CallableCollection
     */
    public function getEventHandlerMap(): CallableCollection
    {
        if (null === $this->eventHandlerMap) {
            $this->eventHandlerMap = new CallableCollection(
                [
                    AccessTokenCreatedEvent::class  => [AccessTokenCreatedEventHandler::class],
                    AccessTokenRevokedEvent::class  => [AccessTokenRevokedEventHandler::class],
                    RefreshTokenCreatedEvent::class => [RefreshTokenCreatedEventHandler::class],
                    RefreshTokenRevokedEvent::class => [RefreshTokenRevokedEventHandler::class],
                    ClientCreatedEvent::class       => [ClientCreatedEventHandler::class],
                    ClientDeletedEvent::class       => [ClientDeletedEventHandler::class],
                    ClientUpdatedEvent::class       => [ClientUpdatedEventHandler::class],
                ],
                $this->getServiceLocatorAwareCallableResolver()
            );
        }

        return $this->eventHandlerMap;
    }

    /**
     * @var null|PublicMessageRecorder
     */
    private $publicMessageRecorder = null;

    /**
     * @return PublicMessageRecorder
     */
    public function getPublicMessageRecorder(): PublicMessageRecorder
    {
        if (null === $this->publicMessageRecorder) {
            $this->publicMessageRecorder = new PublicMessageRecorder();
        }

        return $this->publicMessageRecorder;
    }

    /**
     * @var null|ResponseFactoryInterface
     */
    private $responseFactory = null;

    /**
     * @return ResponseFactoryInterface
     */
    public function getResponseFactory(): ResponseFactoryInterface
    {
        if (null === $this->responseFactory) {
            $this->responseFactory = new ResponseFactory();
        }

        return $this->responseFactory;
    }

    /**
     * @var null|RuleManager
     */
    private $ruleManager = null;

    /**
     * @return RuleManager
     */
    public function getRuleManager(): RuleManager
    {
        if (null === $this->ruleManager) {
            $this->ruleManager = new RuleManager();
            $this->ruleManager
                ->appendRule(new ClientIdRule())
                ->appendRule(new ClientRegistrationManagementRule())
                ->appendRule(new CommonParametersRule())
                ->appendRule($this->getGrantTypeFlowRule())
                ->appendRule(new RedirectionUriRule())
                ->appendRule(new ScopeRule($this->getScopeRepository()))
                ->appendRule($this->getSoftwareRule());
        }

        return $this->ruleManager;
    }

    /**
     * @var null|SoftwareRule
     */
    private $softwareRule = null;

    /**
     * @return SoftwareRule
     */
    private function getSoftwareRule(): SoftwareRule
    {
        if (null === $this->softwareRule) {
            $this->softwareRule = new SoftwareRule();
            $this->softwareRule->allowRegistrationWithoutSoftwareStatement();
            $this->softwareRule->enableSoftwareStatementSupport(
                $this->getJwtLoader(),
                $this->getPublicKeys()
            );
        }

        return $this->softwareRule;
    }

    /**
     * @return JWKSetInterface
     */
    private function getPublicKeys(): JWKSetInterface
    {
        return JWKFactory::createPublicKeySet($this->getPrivateKeys());
    }

    /**
     * @var null|JWKSetInterface
     */
    private $softwareStatementPrivateKeys = null;

    /**
     * @return JWKSetInterface
     */
    public function getPrivateKeys(): JWKSetInterface
    {
        if (null === $this->softwareStatementPrivateKeys) {
            $this->softwareStatementPrivateKeys = JWKFactory::createStorableKeySet(
                tempnam(sys_get_temp_dir(), 'OAUTH2'),
                [
                    'kty' => 'EC',
                    'alg' => 'ES256',
                    'crv' => 'P-256',
                ],
                2
            );
        }

        return $this->softwareStatementPrivateKeys;
    }

    /**
     * @var null|ServerRequestFactoryInterface
     */
    private $serverRequestFactory = null;

    /**
     * @return ServerRequestFactoryInterface
     */
    public function getServerRequestFactory(): ServerRequestFactoryInterface
    {
        if (null === $this->serverRequestFactory) {
            $this->serverRequestFactory = new ServerRequestFactory();
        }

        return $this->serverRequestFactory;
    }

    /**
     * @var null|ServiceLocatorAwareCallableResolver
     */
    private $serviceLocatorAwareCallableResolver = null;

    /**
     * @return ServiceLocatorAwareCallableResolver
     */
    public function getServiceLocatorAwareCallableResolver(): ServiceLocatorAwareCallableResolver
    {
        if (null === $this->serviceLocatorAwareCallableResolver) {
            $this->serviceLocatorAwareCallableResolver = new ServiceLocatorAwareCallableResolver(
                $this->getServiceLocator()
            );
        }

        return $this->serviceLocatorAwareCallableResolver;
    }

    /**
     * @var null|ServiceLocator
     */
    private $serviceLocator = null;

    /**
     * @return ServiceLocator
     */
    public function getServiceLocator(): ServiceLocator
    {
        if (null === $this->serviceLocator) {
            $this->serviceLocator = new ServiceLocator(
                $this->getContainer()
            );
        }

        return $this->serviceLocator;
    }

    /**
     * @var null|StreamFactoryInterface
     */
    private $streamFactory = null;

    /**
     * @return StreamFactoryInterface
     */
    public function getStreamFactory(): StreamFactoryInterface
    {
        if (null === $this->streamFactory) {
            $this->streamFactory = new StreamFactory();
        }

        return $this->streamFactory;
    }

    /**
     * @var null|EventStoreInterface
     */
    private $eventStore = null;

    /**
     * @return EventStoreInterface
     */
    public function getEventStore(): EventStoreInterface
    {
        if (null === $this->eventStore) {
            $this->eventStore = new EventStore();
        }

        return $this->eventStore;
    }

    /**
     * @var null|GrantTypeFlowRule
     */
    private $grantTypeFlowRule = null;

    /**
     * @return GrantTypeFlowRule
     */
    public function getGrantTypeFlowRule(): GrantTypeFlowRule
    {
        if (null === $this->grantTypeFlowRule) {
            $this->grantTypeFlowRule = new GrantTypeFlowRule(
                $this->getGrantTypeManager(),
                $this->getResponseTypeManager()
            );
        }

        return $this->grantTypeFlowRule;
    }

    /**
     * @var null|GrantTypeManagerInterface
     */
    private $grantTypeManager = null;

    /**
     * @return GrantTypeManagerInterface
     */
    public function getGrantTypeManager(): GrantTypeManagerInterface
    {
        if (null === $this->grantTypeManager) {
            $this->grantTypeManager = new GrantTypeManager();
            $this->grantTypeManager->addGrantType($this->getClientCredentialsGrantType());
            $this->grantTypeManager->addGrantType($this->getJWTBearerGrantType());
            $this->grantTypeManager->addGrantType($this->getResourceOwnerPasswordCredentialsGrantType());
            $this->grantTypeManager->addGrantType($this->getRefreshTokenGrantType());
        }

        return $this->grantTypeManager;
    }

    /**
     * @var null|ResponseTypeManagerInterface
     */
    private $responseTypeManager = null;

    /**
     * @return ResponseTypeManagerInterface
     */
    public function getResponseTypeManager(): ResponseTypeManagerInterface
    {
        if (null === $this->responseTypeManager) {
            $this->responseTypeManager = new ResponseTypeManager();
        }

        return $this->responseTypeManager;
    }

    /**
     * @var null|ClientCredentialsGrantType
     */
    private $clientCredentialsGrantType = null;

    /**
     * @return ClientCredentialsGrantType
     */
    public function getClientCredentialsGrantType(): ClientCredentialsGrantType
    {
        if (null === $this->clientCredentialsGrantType) {
            $this->clientCredentialsGrantType = new ClientCredentialsGrantType();
        }

        return $this->clientCredentialsGrantType;
    }

    /**
     * @var null|RefreshTokenGrantType
     */
    private $refreshTokenGrantType = null;

    /**
     * @return RefreshTokenGrantType
     */
    public function getRefreshTokenGrantType(): RefreshTokenGrantType
    {
        if (null === $this->refreshTokenGrantType) {
            $this->refreshTokenGrantType = new RefreshTokenGrantType(
                $this->getRefreshTokenRepository()
            );
        }

        return $this->refreshTokenGrantType;
    }

    /**
     * @var null|ResourceOwnerPasswordCredentialsGrantType
     */
    private $resourceOwnerPasswordCredentialsGrantType = null;

    /**
     * @return ResourceOwnerPasswordCredentialsGrantType
     */
    public function getResourceOwnerPasswordCredentialsGrantType(): ResourceOwnerPasswordCredentialsGrantType
    {
        if (null === $this->resourceOwnerPasswordCredentialsGrantType) {
            $this->resourceOwnerPasswordCredentialsGrantType = new ResourceOwnerPasswordCredentialsGrantType(
                $this->getUserAccountRepository()
            );
            $this->resourceOwnerPasswordCredentialsGrantType->allowRefreshTokenIssuance();
        }

        return $this->resourceOwnerPasswordCredentialsGrantType;
    }

    /**
     * @var null|JWTBearerGrantType
     */
    private $jwtBearerGrantType = null;

    /**
     * @return JWTBearerGrantType
     */
    public function getJWTBearerGrantType(): JWTBearerGrantType
    {
        if (null === $this->jwtBearerGrantType) {
            $this->jwtBearerGrantType = new JWTBearerGrantType(
                $this->getJwtLoader(),
                $this->getClientRepository()
            );
            $this->jwtBearerGrantType->enableEncryptedAssertions(
                false,
                $this->getPrivateKeys()
            );
        }

        return $this->jwtBearerGrantType;
    }

    /**
     * @var null|UserAccountRepositoryInterface
     */
    private $userAccountRepository = null;

    /**
     * @return UserAccountRepositoryInterface
     */
    public function getUserAccountRepository(): UserAccountRepositoryInterface
    {
        if (null === $this->userAccountRepository) {
            $this->userAccountRepository = new UserAccountRepository();
        }

        return $this->userAccountRepository;
    }

    /**
     * @var null|PKCEMethodManagerInterface
     */
    private $pkceMethodManager = null;

    /**
     * @var null|PKCEMethodInterface
     */
    private $pkceMethodPlain = null;

    /**
     * @var null|PKCEMethodInterface
     */
    private $pkceMethodS256 = null;

    /**
     * @return PKCEMethodManagerInterface
     */
    public function getPKCEMethodManager(): PKCEMethodManagerInterface
    {
        if (null === $this->pkceMethodManager) {
            $this->pkceMethodManager = new PKCEMethodManager();
            $this->pkceMethodManager
                ->addPKCEMethod($this->getPKCEMethodPlain())
                ->addPKCEMethod($this->getPKCEMethodS256());
        }

        return $this->pkceMethodManager;
    }

    /**
     * @return PKCEMethodInterface
     */
    protected function getPKCEMethodPlain(): PKCEMethodInterface
    {
        if (null === $this->pkceMethodPlain) {
            $this->pkceMethodPlain = new Plain();
        }

        return $this->pkceMethodPlain;
    }

    /**
     * @return PKCEMethodInterface
     */
    protected function getPKCEMethodS256(): PKCEMethodInterface
    {
        if (null === $this->pkceMethodS256) {
            $this->pkceMethodS256 = new S256();
        }

        return $this->pkceMethodS256;
    }

    /**
     * @var null|ScopeRepositoryInterface
     */
    private $scopeRepository = null;

    /**
     * @var null|ScopePolicyInterface
     */
    private $scopePolicyDefault = null;

    /**
     * @var null|ScopePolicyInterface
     */
    private $scopePolicyError = null;

    /**
     * @return ScopeRepositoryInterface
     */
    public function getScopeRepository(): ScopeRepositoryInterface
    {
        if (null === $this->scopeRepository) {
            $this->scopeRepository = new ScopeRepository(
                $this->getOAuth2ResponseFactory(),
                ['data_read', 'data_write', 'openid', 'profile', 'email', 'phone', 'address', 'offline_access']
            );
            $this->scopeRepository
                ->addScopePolicy($this->getScopePolicyDefault())
                ->addScopePolicy($this->getScopePolicyError());
        }

        return $this->scopeRepository;
    }

    /**
     * @return ScopePolicyInterface
     */
    public function getScopePolicyDefault(): ScopePolicyInterface
    {
        if (null === $this->scopePolicyDefault) {
            $this->scopePolicyDefault = new DefaultScopePolicy([
                'data_read',
            ]);
        }

        return $this->scopePolicyDefault;
    }

    /**
     * @return ScopePolicyInterface
     */
    public function getScopePolicyError(): ScopePolicyInterface
    {
        if (null === $this->scopePolicyError) {
            $this->scopePolicyError = new ErrorScopePolicy();
        }

        return $this->scopePolicyError;
    }

    /**
     * @var null|InitialAccessTokenRepositoryInterface
     */
    private $initialAccessTokenRepository = null;

    /**
     * @var null|InitialAccessTokenMiddleware
     */
    private $initialAccessTokenMiddleware = null;

    /**
     * @return InitialAccessTokenMiddleware
     */
    public function getInitialAccessTokenMiddleware(): InitialAccessTokenMiddleware
    {
        if (null === $this->initialAccessTokenMiddleware) {
            $this->initialAccessTokenMiddleware = new InitialAccessTokenMiddleware(
                $this->getBearerTokenType(),
                $this->getInitialAccessTokenRepository()
            );
        }

        return $this->initialAccessTokenMiddleware;
    }

    /**
     * @var null|BearerToken
     */
    private $bearerTokenType = null;

    /**
     * @return BearerToken
     */
    public function getBearerTokenType(): BearerToken
    {
        if (null === $this->bearerTokenType) {
            $this->bearerTokenType = new BearerToken('**My Service**');
        }

        return $this->bearerTokenType;
    }

    /**
     * @var null|MacToken
     */
    private $macTokenType = null;

    /**
     * @return MacToken
     */
    public function getMacTokenType(): MacToken
    {
        if (null === $this->macTokenType) {
            $this->macTokenType = new MacToken();
        }

        return $this->macTokenType;
    }

    /**
     * @return InitialAccessTokenRepositoryInterface
     */
    public function getInitialAccessTokenRepository(): InitialAccessTokenRepositoryInterface
    {
        if (null === $this->initialAccessTokenRepository) {
            $this->initialAccessTokenRepository = new InitialAccessTokenRepository(
                $this->getPublicMessageRecorder()
            );
        }

        return $this->initialAccessTokenRepository;
    }

    /**
     * @var null|JWTCreator
     */
    private $jwtCreator = null;

    /**
     * @var null|JWTLoader
     */
    private $jwtLoader = null;

    /**
     * @var null|Signer
     */
    private $jwtSigner = null;

    /**
     * @var null|Verifier
     */
    private $jwtVerifier = null;

    /**
     * @var null|Encrypter
     */
    private $jwtEncrypter = null;

    /**
     * @var null|Decrypter
     */
    private $jwtDecrypter = null;

    /**
     * @var null|CheckerManager
     */
    private $jwtCheckerManager = null;

    /**
     * @return JWTCreator
     */
    public function getJwtCreator(): JWTCreator
    {
        if (null === $this->jwtCreator) {
            $this->jwtCreator = new JWTCreator(
                $this->getJwtSigner()
            );
            $this->jwtCreator->enableEncryptionSupport(
                $this->getJwtEncrypter()
            );
        }

        return $this->jwtCreator;
    }

    /**
     * @return JWTLoader
     */
    public function getJwtLoader(): JWTLoader
    {
        if (null === $this->jwtLoader) {
            $this->jwtLoader = new JWTLoader(
                $this->getJwtChecker(),
                $this->getJwtVerifier()
            );

            $this->jwtLoader->enableDecryptionSupport(
                $this->getJwtDecrypter()
            );
        }

        return $this->jwtLoader;
    }

    private function getJwtChecker(): CheckerManager
    {
        if (null === $this->jwtCheckerManager) {
            $this->jwtCheckerManager = new CheckerManager();
        }

        return $this->jwtCheckerManager;
    }

    private function getJwtSigner(): Signer
    {
        if (null === $this->jwtSigner) {
            $this->jwtSigner = new Signer([
                'HS256',
                'RS256',
                'ES256',
            ]);
        }

        return $this->jwtSigner;
    }

    private function getJwtVerifier(): Verifier
    {
        if (null === $this->jwtVerifier) {
            $this->jwtVerifier = new Verifier([
                'HS256',
                'RS256',
                'ES256',
            ]);
        }

        return $this->jwtVerifier;
    }

    private function getJwtEncrypter(): Encrypter
    {
        if (null === $this->jwtEncrypter) {
            $this->jwtEncrypter = new Encrypter(
                ['RSA-OAEP', 'RSA-OAEP-256'],
                ['A256GCM', 'A256CBC-HS512'],
                ['DEF']
            );
        }

        return $this->jwtEncrypter;
    }

    private function getJwtDecrypter(): Decrypter
    {
        if (null === $this->jwtDecrypter) {
            $this->jwtDecrypter = new Decrypter(
                ['RSA-OAEP', 'RSA-OAEP-256'],
                ['A256GCM', 'A256CBC-HS512'],
                ['DEF']
            );
        }

        return $this->jwtDecrypter;
    }

    /**
     * @var null|ClientConfigurationEndpoint
     */
    private $clientConfigurationEndpoint = null;

    /**
     * @return ClientConfigurationEndpoint
     */
    public function getClientConfigurationEndpoint(): ClientConfigurationEndpoint
    {
        if (null === $this->clientConfigurationEndpoint) {
            $this->clientConfigurationEndpoint = new ClientConfigurationEndpoint(
                $this->getBearerTokenType(),
                $this->getCommandBus(),
                $this->getResponseFactory(),
                $this->getJsonEncoder()
            );
        }

        return $this->clientConfigurationEndpoint;
    }

    /**
     * @var null|JsonEncoder
     */
    private $jsonEncoder = null;

    /**
     * @return JsonEncoder
     */
    public function getJsonEncoder(): JsonEncoder
    {
        if (null === $this->jsonEncoder) {
            $this->jsonEncoder = new JsonEncoder();
        }

        return $this->jsonEncoder;
    }

    /**
     * @var null|JsonDecoder
     */
    private $jsonDecoder = null;

    /**
     * @return JsonDecoder
     */
    public function getJsonDecoder(): JsonDecoder
    {
        if (null === $this->jsonDecoder) {
            $this->jsonDecoder = new JsonDecoder();
        }

        return $this->jsonDecoder;
    }

    /**
     * @var null|Pipe
     */
    private $clientConfigurationPipe = null;

    /**
     * @return Pipe
     */
    public function getClientConfigurationPipe(): Pipe
    {
        if (null === $this->clientConfigurationPipe) {
            $this->clientConfigurationPipe = new Pipe();

            $this->clientConfigurationPipe->appendMiddleware($this->getOAuth2ResponseMiddleware());
            $this->clientConfigurationPipe->appendMiddleware($this->getClientConfigurationEndpoint());
        }

        return $this->clientConfigurationPipe;
    }

    /**
     * @var null|TokenTypeHintManagerInterface
     */
    private $tokenTypeHintManager = null;

    /**
     * @return TokenTypeHintManagerInterface
     */
    public function getTokenTypeHintManager(): TokenTypeHintManagerInterface
    {
        if (null === $this->tokenTypeHintManager) {
            $this->tokenTypeHintManager = new TokenTypeHintManager();
            $this->tokenTypeHintManager->addTokenTypeHint($this->getAccessTokenTypeHint()); // Access Token
            $this->tokenTypeHintManager->addTokenTypeHint($this->getRefreshTokenTypeHint()); // Refresh Token
            $this->tokenTypeHintManager->addTokenTypeHint($this->getAuthCodeTypeHint()); // Auth Code
        }

        return $this->tokenTypeHintManager;
    }

    /**
     * @var null|TokenRevocationGetEndpoint
     */
    private $tokenRevocationGetEndpoint = null;

    /**
     * @return TokenRevocationGetEndpoint
     */
    public function getTokenRevocationGetEndpoint(): TokenRevocationGetEndpoint
    {
        if (null === $this->tokenRevocationGetEndpoint) {
            $this->tokenRevocationGetEndpoint = new TokenRevocationGetEndpoint(
                $this->getTokenTypeHintManager(),
                $this->getResponseFactory(),
                $this->getJsonEncoder(),
                true
            );
        }

        return $this->tokenRevocationGetEndpoint;
    }

    /**
     * @var null|TokenRevocationPostEndpoint
     */
    private $tokenRevocationPostEndpoint = null;

    /**
     * @return TokenRevocationPostEndpoint
     */
    public function getTokenRevocationPostEndpoint(): TokenRevocationPostEndpoint
    {
        if (null === $this->tokenRevocationPostEndpoint) {
            $this->tokenRevocationPostEndpoint = new TokenRevocationPostEndpoint(
                $this->getTokenTypeHintManager(),
                $this->getResponseFactory(),
                $this->getJsonEncoder()
            );
        }

        return $this->tokenRevocationPostEndpoint;
    }

    /**
     * @var null|Pipe
     */
    private $tokenRevocationPipe = null;

    /**
     * @return Pipe
     */
    public function getTokenRevocationPipe(): Pipe
    {
        if (null === $this->tokenRevocationPipe) {
            $this->tokenRevocationPipe = new Pipe();

            $this->tokenRevocationPipe->appendMiddleware($this->getOAuth2ResponseMiddleware());
            $this->tokenRevocationPipe->appendMiddleware($this->getClientAuthenticationMiddlewareWithRequirement());
            $this->tokenRevocationPipe->appendMiddleware($this->getTokenRevocationHttpMethod());
        }

        return $this->tokenRevocationPipe;
    }

    /**
     * @var null|HttpMethod
     */
    private $tokenRevocationHttpMethod = null;

    /**
     * @return HttpMethod
     */
    public function getTokenRevocationHttpMethod(): HttpMethod
    {
        if (null === $this->tokenRevocationHttpMethod) {
            $this->tokenRevocationHttpMethod = new HttpMethod();
            $this->tokenRevocationHttpMethod->addMiddleware('POST', $this->getTokenRevocationPostEndpoint());
            $this->tokenRevocationHttpMethod->addMiddleware('GET', $this->getTokenRevocationGetEndpoint());
        }

        return $this->tokenRevocationHttpMethod;
    }

    /**
     * @var null|TokenIntrospectionEndpoint
     */
    private $tokenIntrospectionEndpoint = null;

    /**
     * @return TokenIntrospectionEndpoint
     */
    public function getTokenIntrospectionEndpoint(): TokenIntrospectionEndpoint
    {
        if (null === $this->tokenIntrospectionEndpoint) {
            $this->tokenIntrospectionEndpoint = new TokenIntrospectionEndpoint(
                $this->getTokenTypeHintManager(),
                $this->getResponseFactory(),
                $this->getJsonEncoder()
            );
        }

        return $this->tokenIntrospectionEndpoint;
    }

    /**
     * @var null|Pipe
     */
    private $tokenIntrospectionPipe = null;

    /**
     * @return Pipe
     */
    public function getTokenIntrospectionPipe(): Pipe
    {
        if (null === $this->tokenIntrospectionPipe) {
            $this->tokenIntrospectionPipe = new Pipe();

            $this->tokenIntrospectionPipe->appendMiddleware($this->getOAuth2ResponseMiddleware());
            $this->tokenIntrospectionPipe->appendMiddleware($this->getClientAuthenticationMiddlewareWithRequirement());
            $this->tokenIntrospectionPipe->appendMiddleware($this->getTokenIntrospectionHttpMethod());
        }

        return $this->tokenIntrospectionPipe;
    }

    /**
     * @var null|HttpMethod
     */
    private $tokenIntrospectionHttpMethod = null;

    /**
     * @return HttpMethod
     */
    public function getTokenIntrospectionHttpMethod(): HttpMethod
    {
        if (null === $this->tokenIntrospectionHttpMethod) {
            $this->tokenIntrospectionHttpMethod = new HttpMethod();
            $this->tokenIntrospectionHttpMethod->addMiddleware('POST', $this->getTokenIntrospectionEndpoint());
        }

        return $this->tokenIntrospectionHttpMethod;
    }

    /**
     * @var null|AccessTokenTypeHint
     */
    private $accessTokenTypeHint = null;

    /**
     * @return AccessTokenTypeHint
     */
    public function getAccessTokenTypeHint(): AccessTokenTypeHint
    {
        if (null === $this->accessTokenTypeHint) {
            $this->accessTokenTypeHint = new AccessTokenTypeHint(
                $this->getAccessTokenRepository(),
                $this->getCommandBus()
            );
        }

        return $this->accessTokenTypeHint;
    }

    /**
     * @var null|RefreshTokenTypeHint
     */
    private $refreshTokenTypeHint = null;

    /**
     * @return RefreshTokenTypeHint
     */
    public function getRefreshTokenTypeHint(): RefreshTokenTypeHint
    {
        if (null === $this->refreshTokenTypeHint) {
            $this->refreshTokenTypeHint = new RefreshTokenTypeHint(
                $this->getRefreshTokenRepository(),
                $this->getCommandBus()
            );
        }

        return $this->refreshTokenTypeHint;
    }

    /**
     * @var null|AuthCodeTypeHint
     */
    private $authCodeTypeHint = null;

    /**
     * @return AuthCodeTypeHint
     */
    public function getAuthCodeTypeHint(): AuthCodeTypeHint
    {
        if (null === $this->authCodeTypeHint) {
            $this->authCodeTypeHint = new AuthCodeTypeHint(
                $this->getAuthorizationCodeRepository(),
                $this->getCommandBus()
            );
        }

        return $this->authCodeTypeHint;
    }

    /**
     * @var null|AccessTokenRepositoryInterface
     */
    private $accessTokenRepository = null;

    /**
     * @return AccessTokenRepositoryInterface
     */
    public function getAccessTokenRepository(): AccessTokenRepositoryInterface
    {
        if (null === $this->accessTokenRepository) {
            $this->accessTokenRepository = new AccessTokenRepository(
                $this->getPublicMessageRecorder()
            );
        }

        return $this->accessTokenRepository;
    }

    /**
     * @var null|RefreshTokenRepositoryInterface
     */
    private $refreshTokenRepository = null;

    /**
     * @return RefreshTokenRepositoryInterface
     */
    public function getRefreshTokenRepository(): RefreshTokenRepositoryInterface
    {
        if (null === $this->refreshTokenRepository) {
            $this->refreshTokenRepository = new RefreshTokenRepository();
        }

        return $this->refreshTokenRepository;
    }

    /**
     * @var null|AuthCodeRepositoryInterface
     */
    private $authCodeRepository = null;

    /**
     * @return AuthCodeRepositoryInterface
     */
    public function getAuthorizationCodeRepository(): AuthCodeRepositoryInterface
    {
        if (null === $this->authCodeRepository) {
            $this->authCodeRepository = new AuthCodeRepository(
                $this->getPublicMessageRecorder()
            );
        }

        return $this->authCodeRepository;
    }

    /**
     * @var null|RevokeAccessTokenCommandHandler
     */
    private $revokeAccessTokenCommandHandler = null;

    /**
     * @return RevokeAccessTokenCommandHandler
     */
    public function getRevokeAccessTokenCommandHandler(): RevokeAccessTokenCommandHandler
    {
        if (null === $this->revokeAccessTokenCommandHandler) {
            $this->revokeAccessTokenCommandHandler = new RevokeAccessTokenCommandHandler(
                $this->getAccessTokenRepository(),
                $this->getPublicMessageRecorder()
            );
        }

        return $this->revokeAccessTokenCommandHandler;
    }

    /**
     * @var null|AccessTokenRevokedEventHandler
     */
    private $accessTokenRevokedEventHandler = null;

    /**
     * @return AccessTokenRevokedEventHandler
     */
    public function getAccessTokenRevokedEventHandler(): AccessTokenRevokedEventHandler
    {
        if (null === $this->accessTokenRevokedEventHandler) {
            $this->accessTokenRevokedEventHandler = new AccessTokenRevokedEventHandler();
        }

        return $this->accessTokenRevokedEventHandler;
    }

    /**
     * @var null|AccessTokenCreatedEventHandler
     */
    private $accessTokenCreatedEventHandler = null;

    /**
     * @return AccessTokenCreatedEventHandler
     */
    public function getAccessTokenCreatedEventHandler(): AccessTokenCreatedEventHandler
    {
        if (null === $this->accessTokenCreatedEventHandler) {
            $this->accessTokenCreatedEventHandler = new AccessTokenCreatedEventHandler();
        }

        return $this->accessTokenCreatedEventHandler;
    }

    /**
     * @var null|RevokeAccessTokenCommandHandler
     */
    private $revokeRefreshTokenCommandHandler = null;

    /**
     * @return RevokeRefreshTokenCommandHandler
     */
    public function getRevokeRefreshTokenCommandHandler(): RevokeRefreshTokenCommandHandler
    {
        if (null === $this->revokeRefreshTokenCommandHandler) {
            $this->revokeRefreshTokenCommandHandler = new RevokeRefreshTokenCommandHandler(
                $this->getRefreshTokenRepository(),
                $this->getPublicMessageRecorder()
            );
        }

        return $this->revokeRefreshTokenCommandHandler;
    }

    /**
     * @var null|RefreshTokenRevokedEventHandler
     */
    private $refreshTokenRevokedEventHandler = null;

    /**
     * @return RefreshTokenRevokedEventHandler
     */
    public function getRefreshTokenRevokedEventHandler(): RefreshTokenRevokedEventHandler
    {
        if (null === $this->refreshTokenRevokedEventHandler) {
            $this->refreshTokenRevokedEventHandler = new RefreshTokenRevokedEventHandler();
        }

        return $this->refreshTokenRevokedEventHandler;
    }

    /**
     * @var null|CodeResponseType
     */
    private $grantCodeResponseType = null;

    /**
     * @return CodeResponseType
     */
    public function getCodeResponseType(): CodeResponseType
    {
        if (null === $this->grantCodeResponseType) {
            /*$this->grantCodeResponseType = new CodeResponseType(

            );
            $this->grantCodeResponseType->*/
        }

        return $this->grantCodeResponseType;
    }

    /**
     * @var null|ImplicitResponseType
     */
    private $grantImplicitResponseType = null;

    /**
     * @return ImplicitResponseType
     */
    public function getImplicitResponseType(): ImplicitResponseType
    {
        if (null === $this->grantImplicitResponseType) {
            /*$this->grantImplicitResponseType = new ImplicitResponseType(
                $this->getAccessTokenHint(),
                $this->getAccessTokenRepository()
            );*/
        }

        return $this->grantImplicitResponseType;
    }

    /**
     * @var null|TokenEndpoint
     */
    private $tokenEndpoint = null;

    /**
     * @return TokenEndpoint
     */
    public function getTokenEndpoint(): TokenEndpoint
    {
        if (null === $this->tokenEndpoint) {
            $this->tokenEndpoint = new TokenEndpoint(
                $this->getResponseFactory(),
                $this->getCommandBus(),
                $this->getTokenTypeManager(),
                $this->getJsonEncoder()
            );
            $this->tokenEndpoint->enableScopeSupport($this->getScopeRepository());
        }

        return $this->tokenEndpoint;
    }

    /**
     * @var null|TokenTypeManagerInterface
     */
    private $tokenTypeManager = null;

    /**
     * @return TokenTypeManagerInterface
     */
    public function getTokenTypeManager(): TokenTypeManagerInterface
    {
        if (null === $this->tokenTypeManager) {
            $this->tokenTypeManager = new TokenTypeManager();
            $this->tokenTypeManager->addTokenType($this->getBearerTokenType());
            $this->tokenTypeManager->addTokenType($this->getMacTokenType());
        }

        return $this->tokenTypeManager;
    }

    /**
     * @var null|GrantTypeMiddleware
     */
    private $grantTypeMiddleware = null;

    /**
     * @return GrantTypeMiddleware
     */
    public function getGrantTypeMiddleware(): GrantTypeMiddleware
    {
        if (null === $this->grantTypeMiddleware) {
            $this->grantTypeMiddleware = new GrantTypeMiddleware(
                $this->getGrantTypeManager()
            );
        }

        return $this->grantTypeMiddleware;
    }

    /**
     * @var null|Pipe
     */
    private $tokenEndpointPipe = null;

    /**
     * @return Pipe
     */
    public function getTokenEndpointPipe(): Pipe
    {
        if (null === $this->tokenEndpointPipe) {
            $this->tokenEndpointPipe = new Pipe();
            $this->tokenEndpointPipe->appendMiddleware($this->getOAuth2ResponseMiddleware());
            $this->tokenEndpointPipe->appendMiddleware($this->getClientAuthenticationMiddleware());
            $this->tokenEndpointPipe->appendMiddleware($this->getGrantTypeMiddleware());
            $this->tokenEndpointPipe->appendMiddleware($this->getTokenTypeMiddleware());
            $this->tokenEndpointPipe->appendMiddleware($this->getTokenEndpoint());
        }

        return $this->tokenEndpointPipe;
    }

    /**
     * @var null|TokenTypeMiddleware
     */
    private $tokenTypeMiddleware = null;

    /**
     * @return TokenTypeMiddleware
     */
    public function getTokenTypeMiddleware(): TokenTypeMiddleware
    {
        if (null === $this->tokenTypeMiddleware) {
            $this->tokenTypeMiddleware = new TokenTypeMiddleware(
                $this->getTokenTypeManager(),
                true
            );
        }

        return $this->tokenTypeMiddleware;
    }

    /**
     * @var null|CreateAccessTokenCommandHandler
     */
    private $createAccessTokenCommandHandler = null;

    /**
     * @return CreateAccessTokenCommandHandler
     */
    public function getCreateAccessTokenCommandHandler(): CreateAccessTokenCommandHandler
    {
        if (null === $this->createAccessTokenCommandHandler) {
            $this->createAccessTokenCommandHandler = new CreateAccessTokenCommandHandler(
                $this->getAccessTokenRepository(),
                $this->getPublicMessageRecorder()
            );
        }

        return $this->createAccessTokenCommandHandler;
    }
}
