<?php

namespace OAuth2\Client;

/**
 * This interface is for unregistered clients.
 * These clients have an ID, but the server can get the client details.
 * Us this client type with caution!
 *
 * @see http://tools.ietf.org/html/rfc6749#section-2.1
 */
abstract class UnregisteredClient extends Client
{
}
