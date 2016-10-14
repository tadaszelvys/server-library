<?php

/*
 * The MIT License (MIT)
 *
 * Copyright (c) 2014-2016 Spomky-Labs
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file for details.
 */

/*
 * This is a small controller that provides several routes.
 * These routes are used by the test cases
 */

use Symfony\Component\HttpFoundation\JsonResponse;
use Symfony\Component\HttpFoundation\Response;

require_once __DIR__.'/../../vendor/autoload.php';

$app = new Silex\Application();

$app->match(
    'empty_sector_identifier_uri',
    getEmptySectorIdentifierUri()
);

$app->match(
    'sector_identifier_uri',
    getSectorIdentifierUri()
);

$app->match(
    'sector_identifier_uri_with_bad_values',
    getSectorIdentifierUriWithBadValues()
);

$app->match(
    'sector_identifier_uri_with_bad_scheme',
    getSectorIdentifierUriWithBadScheme()
);

$app->match(
    'signed_request',
    getSignedRequest()
);

$app->match(
    'signed_and_encrypted_request',
    getSignedAndEncryptedRequest()
);

$app->run();

function getEmptySectorIdentifierUri()
{
    return function () {
        return new JsonResponse([]);
    };
}

function getSectorIdentifierUri()
{
    return function () {
        return new JsonResponse([
            'https://url1.test.com',
            'https://url2.example.org',
        ]);
    };
}

function getSectorIdentifierUriWithBadValues()
{
    return function () {
        return new JsonResponse([
            'foo',
            'Bar',
        ]);
    };
}

function getSectorIdentifierUriWithBadScheme()
{
    return function () {
        return new JsonResponse([
            'ftp://url1.test.com',
            'https://url2.example.org',
        ]);
    };
}

function getSignedRequest()
{
    return function () {
        $jws = file_get_contents(__DIR__.'/../signed_request');
        return new Response($jws);
    };
}

function getSignedAndEncryptedRequest()
{
    return function () {
        $jwe = file_get_contents(__DIR__.'/../signed_and_encrypted_request');
        return new Response($jwe);
    };
}
