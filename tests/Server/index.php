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
        return new Response(
            'eyJraWQiOiJKV0syIiwiY3R5IjoiSldUIiwiYWxnIjoiSFM1MTIifQ.eyJpYXQiOjE0NTg1ODQ2NDEsIm5iZiI6MTQ1ODU4NDY0MSwiaXNzIjoiand0MSIsImF1ZCI6Imh0dHBzOlwvXC9zZXJ2ZXIuZXhhbXBsZS5jb20iLCJyZXNwb25zZV90eXBlIjoidG9rZW4iLCJjbGllbnRfaWQiOiJqd3QxIiwicmVkaXJlY3RfdXJpIjoiaHR0cDpcL1wvZXhhbXBsZS5jb21cL3Rlc3Q_Z29vZD1mYWxzZSIsInNjb3BlIjoib3BlbmlkIHNjb3BlMSBzY29wZTIiLCJzdGF0ZSI6IjAxMjM0NTY3OSIsIm5vbmNlIjoibi0wUzZfV3pBMk1qIn0.7OjrZLPOht7FM-0_1hmZ6pW4Kb1X5vqi7w3XBlwF9t6Eu2KyiXOB8yeTL6zfaC2k_o2IELjLmVSG-irbz0r9vw'
        );
    };
}

function getSignedAndEncryptedRequest()
{
    return function () {
        return new Response(
            'eyJraWQiOiJKV0sxIiwiY3R5IjoiSldUIiwiYWxnIjoiQTI1NktXIiwiZW5jIjoiQTI1NkNCQy1IUzUxMiIsImF1ZCI6Ik15IEF1dGhvcml6YXRpb24gU2VydmVyIiwiaXNzIjoiand0MSJ9.TXfP1GTkqksbTt4enEaQTj7FJmRXDFvh0j0W6yX6xKeuJIr1EYt-1okXXRzann7dm2-KRfbbSKnaF_wT7MqTI80TFzeT5ROE.nqtRYM0js0qr4Ps6b2tcSg.P5nMLbXUZ6OQAlrznQ124Pj1SDOfk460rEXw7du__RHVmXhfHlVpl7w0r3EsO88XpRkrEVwdEKqNAAEcggg7iss2G1wbUezJIKBFMV6qjMeP6gNO5Kot0-L3ueO5VxKFLCyoijAeKJglJ3RlVJ54IWDvR62lGomk0ZzYijZgqWbNkmKdb6NkdfZ_uJHGZOilhlmS8hYtQIZfIylZ2VMPlsv9ZsLsJYH5QFsBctRIEdpkFT23W_EwLQ3NCcd_biuDEcp5DVLyCI_yd7SfQIRQNNz8KRytDrDo7u0yUS3stJ9E708h_8n5Mi6jYDjmLXA-azlEHL_hV4iujnyoUY7ZNlgU9RqIy_CyqEPVSevzqFS4hQm15n56FqwkdQ8OvR9vEbGc6E59VS3gFBtr4la_lWpbEOGTD2glVtP1KP4IwIMLZ4awOit2ZqEZiP3OXCgecj6Rf4CMLY2rQW-kUXKef7mAJ5LYWfI0EwxZRqT6B5m3QfBK_4YhRhuROrVn_nA4_mNBgdbcFJykMOOGqGKKQTAmPzzhnWnHBgedRS95RTSkx7UznQbd6aLYz5ZSL-keBtq3Bl4wrxcaFH8lrTVv5Zzj8LhBriveIPiBQkvUhWSqzPUIJgHmD_JXAxkHCp9F5VjCnT7fshjT8V6pZkPkkg.SUTw8Bh1FR23_WBrRLt_-Tz6VYsmYAcwAjjKZxC-hZw'
        );
    };
}
