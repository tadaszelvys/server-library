<?php

/*
 * The MIT License (MIT)
 *
 * Copyright (c) 2014-2016 Spomky-Labs
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file for details.
 */

namespace OAuth2\User;

use OAuth2\ResourceOwner\ResourceOwnerTrait;

/**
 * This interface must be implemented by end-user classes.
 */
class User implements UserInterface
{
    use ResourceOwnerTrait;
    use UserTrait;
}
