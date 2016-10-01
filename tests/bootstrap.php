<?php

/*
 * The MIT License (MIT)
 *
 * Copyright (c) 2014-2016 Spomky-Labs
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file for details.
 */

if (PHP_SESSION_ACTIVE !== session_status()) {
    session_start();
}

require_once __DIR__.'/../vendor/autoload.php';
