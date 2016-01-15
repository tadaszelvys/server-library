<?php

/*
 * The MIT License (MIT)
 *
 * Copyright (c) 2014-2016 Spomky-Labs
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file for details.
 */

namespace OAuth2\Client;

/**
 * Interface ConfidentialClientInterface
 *
 * This interface is for all confidential clients.
 * Client managers that support this client type MUST authenticate the client using the request
 * and any other client properties.
 *
 * @see http://tools.ietf.org/html/rfc6749#section-2.1
 */
interface ConfidentialClientInterface extends RegisteredClientInterface
{
}
