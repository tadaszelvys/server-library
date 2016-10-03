<?php

/*
 * The MIT License (MIT)
 *
 * Copyright (c) 2014-2016 Spomky-Labs
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file for details.
 */

namespace OAuth2\Test\Functional;

use OAuth2\Test\Base;
use Zend\Diactoros\Response;

/**
 * @group ClientRegistration
 */
class ClientRegistrationEndpointTest extends Base
{
    public function testRequestNotSecured()
    {
        $request = $this->createRequest('/', 'POST');

        $response = new Response();
        $this->getClientRegistrationEndpoint()->register($request, $response);
        $response->getBody()->rewind();

        $this->assertEquals(400, $response->getStatusCode());
        $this->assertEquals('{"error":"invalid_request","error_description":"The request must be secured.","error_uri":"https:\/\/foo.test\/Error\/BadRequest\/invalid_request"}', $response->getBody()->getContents());
    }

    public function testNoAuthenticationMethod()
    {
        $request = $this->createRequest('/', 'POST', [], ['HTTPS' => 'on']);

        $response = new Response();
        $this->getClientRegistrationEndpoint()->register($request, $response);
        $response->getBody()->rewind();
        $content = $response->getBody()->getContents();

        $this->assertEquals(400, $response->getStatusCode());
        $this->assertEquals('{"error":"invalid_request","error_description":"The parameter \"token_endpoint_auth_method\" is missing.","error_uri":"https:\/\/foo.test\/Error\/BadRequest\/invalid_request"}', $content);
    }

    public function testUnsupportedAuthenticationMethod()
    {
        $request = $this->createRequest('/', 'POST', ['token_endpoint_auth_method' => 'foo'], ['HTTPS' => 'on']);

        $response = new Response();
        $this->getClientRegistrationEndpoint()->register($request, $response);
        $response->getBody()->rewind();
        $content = $response->getBody()->getContents();

        $this->assertEquals(400, $response->getStatusCode());
        $this->assertEquals('{"error":"invalid_request","error_description":"The token endpoint authentication method \"foo\" is not supported. Please use one of the following values: [\"none\",\"client_secret_basic\",\"client_secret_post\",\"client_secret_jwt\",\"private_key_jwt\"]","error_uri":"https:\/\/foo.test\/Error\/BadRequest\/invalid_request"}', $content);
    }

    public function testKeysNotSetForPrivateKeyJWTAuthenticationMethod()
    {
        $request = $this->createRequest('/', 'POST', ['token_endpoint_auth_method' => 'private_key_jwt'], ['HTTPS' => 'on']);

        $response = new Response();
        $this->getClientRegistrationEndpoint()->register($request, $response);
        $response->getBody()->rewind();
        $content = $response->getBody()->getContents();

        $this->assertEquals(400, $response->getStatusCode());
        $this->assertEquals('{"error":"invalid_request","error_description":"The parameter \"jwks\" or \"jwks_uri\" must be set.","error_uri":"https:\/\/foo.test\/Error\/BadRequest\/invalid_request"}', $content);
    }

    public function testClientCreatedWithPrivateKeyJWTAuthenticationMethod()
    {
        $keyset_as_array = json_decode('{"keys":[{"kid":"KEY","kty":"RSA","n":"3nsn7a7nHV_tfNlbH11p_9Bw6ZVDEjT6K4_GD9iTJ8wmYpbOSFFaqEdckeWa5GJThIAUrxjwXLDt41kldYuT295Rmr4EUG5fp-kzgXM4Y7TrWdevHY7kVddz8FWMU7CerJfVjqS3Z1u-V1ODdG_JtAoxdn0xBnab2a-lzCLeoPqKebJnfGKOUaJjwuKz8VkMMRPgT186z8TE-tBTgkGUF_qXF4P51_wZgsR1G-hc7p8WFzBcfX6SOKzyaRmxEhLAH-bpZwSLAG--7Hss0Rkfm7lub4xaG0V8OlePXjN0_E1u66splePcTswFQaXqIxEzWtCJKytF4OQViGNj8-ENew","e":"AQAB"}]}', true);

        $request = $this->createRequest('/', 'POST', ['token_endpoint_auth_method' => 'private_key_jwt', 'jwks' => $keyset_as_array], ['HTTPS' => 'on']);

        $response = new Response();
        $this->getClientRegistrationEndpoint()->register($request, $response);
        $response->getBody()->rewind();
        $content = $response->getBody()->getContents();

        $this->assertEquals(200, $response->getStatusCode());
        $client_config = json_decode($content, true);

        $this->assertTrue(array_key_exists('public_id', $client_config));
        $this->assertTrue(array_key_exists('jwks', $client_config));
        $this->assertTrue(array_key_exists('token_endpoint_auth_method', $client_config));
        $this->assertEquals('private_key_jwt', $client_config['token_endpoint_auth_method']);
        $this->assertEquals($keyset_as_array, $client_config['jwks']);
    }

    public function testBadSectorIdentifierUriResponse()
    {
        $request = $this->createRequest('/', 'POST', ['sector_identifier_uri' => 'https://www.google.com', 'token_endpoint_auth_method' => 'none'], ['HTTPS' => 'on']);

        $response = new Response();
        $this->getClientRegistrationEndpoint()->register($request, $response);
        $response->getBody()->rewind();
        $content = $response->getBody()->getContents();

        $this->assertEquals(400, $response->getStatusCode());
        $this->assertEquals('{"error":"invalid_request","error_description":"The provided sector identifier URI is not valid: bad response.","error_uri":"https:\/\/foo.test\/Error\/BadRequest\/invalid_request"}', $content);
    }

    public function testEmptySectorIdentifierUriResponse()
    {
        $request = $this->createRequest('/', 'POST', ['sector_identifier_uri' => 'https://127.0.0.1:8181/empty_sector_identifier_uri', 'token_endpoint_auth_method' => 'none'], ['HTTPS' => 'on']);

        $response = new Response();
        $this->getClientRegistrationEndpoint()->register($request, $response);
        $response->getBody()->rewind();
        $content = $response->getBody()->getContents();

        $this->assertEquals(400, $response->getStatusCode());
        $this->assertEquals('{"error":"invalid_request","error_description":"The provided sector identifier URI is not valid: it must contain at least one URI.","error_uri":"https:\/\/foo.test\/Error\/BadRequest\/invalid_request"}', $content);
    }

    public function testSectorIdentifierUriContainsBadValues()
    {
        $request = $this->createRequest('/', 'POST', ['sector_identifier_uri' => 'https://127.0.0.1:8181/sector_identifier_uri_with_bad_values', 'token_endpoint_auth_method' => 'none'], ['HTTPS' => 'on']);

        $response = new Response();
        $this->getClientRegistrationEndpoint()->register($request, $response);
        $response->getBody()->rewind();
        $content = $response->getBody()->getContents();

        $this->assertEquals(400, $response->getStatusCode());
        $this->assertEquals('{"error":"invalid_request","error_description":"The provided sector identifier URI is not valid: it must contain only URIs.","error_uri":"https:\/\/foo.test\/Error\/BadRequest\/invalid_request"}', $content);
    }

    public function testSectorIdentifierUriContainsUriWithBadScheme()
    {
        $request = $this->createRequest('/', 'POST', ['sector_identifier_uri' => 'https://127.0.0.1:8181/sector_identifier_uri_with_bad_scheme', 'token_endpoint_auth_method' => 'none'], ['HTTPS' => 'on']);

        $response = new Response();
        $this->getClientRegistrationEndpoint()->register($request, $response);
        $response->getBody()->rewind();
        $content = $response->getBody()->getContents();

        $this->assertEquals(400, $response->getStatusCode());
        $this->assertEquals('{"error":"invalid_request","error_description":"The provided sector identifier URI is not valid: it must contain only URIs.","error_uri":"https:\/\/foo.test\/Error\/BadRequest\/invalid_request"}', $content);
    }

    public function testSectorIdentifierUriResponse()
    {
        $request = $this->createRequest('/', 'POST', ['sector_identifier_uri' => 'https://127.0.0.1:8181/sector_identifier_uri', 'token_endpoint_auth_method' => 'none'], ['HTTPS' => 'on']);

        $response = new Response();
        $this->getClientRegistrationEndpoint()->register($request, $response);
        $response->getBody()->rewind();
        $content = $response->getBody()->getContents();

        $this->assertEquals(200, $response->getStatusCode());
        $client_config = json_decode($content, true);

        $this->assertTrue(array_key_exists('public_id', $client_config));
        $this->assertTrue(array_key_exists('sector_identifier_uri', $client_config));
        $this->assertTrue(array_key_exists('token_endpoint_auth_method', $client_config));
        $this->assertEquals('none', $client_config['token_endpoint_auth_method']);
        $this->assertEquals('https://127.0.0.1:8181/sector_identifier_uri', $client_config['sector_identifier_uri']);
    }

    public function testInvalidCharacterInTheScope()
    {
        $request = $this->createRequest('/', 'POST', ['scope' => 'read write &é~', 'token_endpoint_auth_method' => 'none'], ['HTTPS' => 'on']);

        $response = new Response();
        $this->getClientRegistrationEndpoint()->register($request, $response);
        $response->getBody()->rewind();
        $content = $response->getBody()->getContents();

        $this->assertEquals(400, $response->getStatusCode());
        $this->assertEquals('{"error":"invalid_request","error_description":"Invalid characters found in the \"scope\" parameter.","error_uri":"https:\/\/foo.test\/Error\/BadRequest\/invalid_request"}', $content);
    }

    public function testClientCreatedWithScopeAndScopePolicy()
    {
        $request = $this->createRequest('/', 'POST', ['scope' => 'read write', 'default_scope' => 'read', 'scope_policy' => 'default', 'token_endpoint_auth_method' => 'none'], ['HTTPS' => 'on']);

        $response = new Response();
        $this->getClientRegistrationEndpoint()->register($request, $response);
        $response->getBody()->rewind();
        $content = $response->getBody()->getContents();

        $this->assertEquals(200, $response->getStatusCode());
        $client_config = json_decode($content, true);

        $this->assertTrue(array_key_exists('public_id', $client_config));
        $this->assertTrue(array_key_exists('scope', $client_config));
        $this->assertTrue(array_key_exists('scope_policy', $client_config));
        $this->assertTrue(array_key_exists('default_scope', $client_config));
        $this->assertTrue(array_key_exists('token_endpoint_auth_method', $client_config));
        $this->assertEquals('none', $client_config['token_endpoint_auth_method']);
        $this->assertEquals('read write', $client_config['scope']);
        $this->assertEquals('default', $client_config['scope_policy']);
        $this->assertEquals('read', $client_config['default_scope']);
    }

    public function testClientCreatedWithCommonParameters()
    {
        $request = $this->createRequest(
            '/',
            'POST',
            [
                'scope' => 'read write',
                'default_scope' => 'read',
                'scope_policy' => 'default',
                'token_endpoint_auth_method' => 'none',
                'client_name' => 'My Example',
                'client_name#fr' => 'Mon Exemple',
                'software_id' => 'ABCD0123',
                'software_version' => '10.2',
                'policy_uri' => 'http://www.example.com/policy',
                'policy_uri#fr' => 'http://www.example.com/vie_privee',
                'tos_uri' => 'http://www.example.com/tos',
                'tos_uri#fr' => 'http://www.example.com/termes_de_service',
            ],
            ['HTTPS' => 'on']
        );

        $response = new Response();
        $this->getClientRegistrationEndpoint()->register($request, $response);
        $response->getBody()->rewind();
        $content = $response->getBody()->getContents();

        $this->assertEquals(200, $response->getStatusCode());
        $client_config = json_decode($content, true);

        $this->assertTrue(array_key_exists('client_name', $client_config));
        $this->assertTrue(array_key_exists('client_name#fr', $client_config));
        $this->assertTrue(array_key_exists('policy_uri', $client_config));
        $this->assertTrue(array_key_exists('policy_uri#fr', $client_config));
        $this->assertTrue(array_key_exists('tos_uri', $client_config));
        $this->assertTrue(array_key_exists('tos_uri#fr', $client_config));
        $this->assertTrue(array_key_exists('software_id', $client_config));
        $this->assertTrue(array_key_exists('software_version', $client_config));
        $this->assertTrue(array_key_exists('public_id', $client_config));
        $this->assertTrue(array_key_exists('scope', $client_config));
        $this->assertTrue(array_key_exists('scope_policy', $client_config));
        $this->assertTrue(array_key_exists('default_scope', $client_config));
        $this->assertTrue(array_key_exists('token_endpoint_auth_method', $client_config));
        $this->assertEquals('none', $client_config['token_endpoint_auth_method']);
        $this->assertEquals('read write', $client_config['scope']);
        $this->assertEquals('default', $client_config['scope_policy']);
        $this->assertEquals('read', $client_config['default_scope']);

        $this->assertEquals('ABCD0123', $client_config['software_id']);
        $this->assertEquals('10.2', $client_config['software_version']);
        $this->assertEquals('My Example', $client_config['client_name']);
        $this->assertEquals('Mon Exemple', $client_config['client_name#fr']);
        $this->assertEquals('http://www.example.com/tos', $client_config['tos_uri']);
        $this->assertEquals('http://www.example.com/termes_de_service', $client_config['tos_uri#fr']);
        $this->assertEquals('http://www.example.com/policy', $client_config['policy_uri']);
        $this->assertEquals('http://www.example.com/vie_privee', $client_config['policy_uri#fr']);
    }
}
