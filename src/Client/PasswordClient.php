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

use OAuth2\ResourceOwner\ResourceOwnerTrait;

class PasswordClient implements PasswordClientInterface
{
    use ResourceOwnerTrait;
    use ClientTrait;
    use RegisteredClientTrait;
    use ConfidentialClientTrait;
    use PasswordClientTrait;
}
