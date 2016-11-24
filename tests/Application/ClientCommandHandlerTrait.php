<?php

namespace OAuth2\Test\Application;

use OAuth2\Client\Rule\RuleManager;
use OAuth2\Command\Client\CreateClientCommandHandler;
use OAuth2\Command\Client\DeleteClientCommandHandler;
use OAuth2\Command\Client\UpdateClientCommandHandler;
use OAuth2\Test\Stub\ClientRepository;
use SimpleBus\Message\Recorder\PublicMessageRecorder;

trait ClientCommandHandlerTrait
{
    abstract public function getClientRepository(): ClientRepository;
    abstract public function getRuleManager(): RuleManager;
    abstract public function getPublicMessageRecorder(): PublicMessageRecorder;

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
}
