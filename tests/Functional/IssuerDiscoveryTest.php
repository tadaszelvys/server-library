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
 * @group IssuerDiscovery
 */
class IssuerDiscoveryTest extends Base
{
    public function testUnsecuredRequest()
    {
        $request = $this->createRequest();
        $response = new Response();
        $this->getIssuerDiscoveryEndpoint()->handle($request, $response);

        $response->getBody()->rewind();

        $this->assertEquals(400, $response->getStatusCode());
        $this->assertEquals('{"error":"invalid_request","error_description":"The request must be secured.","error_uri":"https:\/\/foo.test\/Error\/BadRequest\/invalid_request"}', $response->getBody()->getContents());
    }

    public function testNoRelInTheRequest()
    {
        $request = $this->createRequest('/', 'GET', [], ['HTTPS' => 'on']);
        $response = new Response();
        $this->getIssuerDiscoveryEndpoint()->handle($request, $response);

        $response->getBody()->rewind();

        $this->assertEquals(400, $response->getStatusCode());
        $this->assertEquals('{"error":"invalid_request","error_description":"The parameter \"rel\" is mandatory.","error_uri":"https:\/\/foo.test\/Error\/BadRequest\/invalid_request"}', $response->getBody()->getContents());
    }

    public function testUnsupportedRelInTheRequest()
    {
        $request = $this->createRequest('/?rel=foo.bar', 'GET', [], ['HTTPS' => 'on']);
        $response = new Response();
        $this->getIssuerDiscoveryEndpoint()->handle($request, $response);

        $response->getBody()->rewind();

        $this->assertEquals(400, $response->getStatusCode());
        $this->assertEquals('{"error":"invalid_request","error_description":"Unsupported \"rel\" parameter value.","error_uri":"https:\/\/foo.test\/Error\/BadRequest\/invalid_request"}', $response->getBody()->getContents());
    }

    public function testMissingResourceInTheRequest()
    {
        $request = $this->createRequest('/?rel=http%3A%2F%2Fopenid.net%2Fspecs%2Fconnect%2F1.0%2Fissuer', 'GET', [], ['HTTPS' => 'on']);
        $response = new Response();
        $this->getIssuerDiscoveryEndpoint()->handle($request, $response);

        $response->getBody()->rewind();

        $this->assertEquals(400, $response->getStatusCode());
        $this->assertEquals('{"error":"invalid_request","error_description":"The parameter \"resource\" is mandatory.","error_uri":"https:\/\/foo.test\/Error\/BadRequest\/invalid_request"}', $response->getBody()->getContents());
    }

    public function testUnsupportedXRIResourceInTheRequest()
    {
        $request = $this->createRequest('/?resource=%40foo.bar&rel=http%3A%2F%2Fopenid.net%2Fspecs%2Fconnect%2F1.0%2Fissuer', 'GET', [], ['HTTPS' => 'on']);
        $response = new Response();
        $this->getIssuerDiscoveryEndpoint()->handle($request, $response);

        $response->getBody()->rewind();

        $this->assertEquals(400, $response->getStatusCode());
        $this->assertEquals('{"error":"invalid_request","error_description":"Unsupported Extensible Resource Identifier (XRI) resource value.","error_uri":"https:\/\/foo.test\/Error\/BadRequest\/invalid_request"}', $response->getBody()->getContents());
    }

    public function testUnsupportedDomainForEmailResourceInTheRequest()
    {
        $request = $this->createRequest('/?resource=acct:user1%40example.com:9000&rel=http%3A%2F%2Fopenid.net%2Fspecs%2Fconnect%2F1.0%2Fissuer', 'GET', [], ['HTTPS' => 'on']);
        $response = new Response();
        $this->getIssuerDiscoveryEndpoint()->handle($request, $response);

        $response->getBody()->rewind();

        $this->assertEquals(400, $response->getStatusCode());
        $this->assertEquals('{"error":"invalid_request","error_description":"Unsupported domain.","error_uri":"https:\/\/foo.test\/Error\/BadRequest\/invalid_request"}', $response->getBody()->getContents());
    }

    public function testUnsupportedDomainForUriResourceInTheRequest()
    {
        $request = $this->createRequest('/?resource=https%3A%2F%2Fexample.com%3A8080%2F%2Buser1&rel=http%3A%2F%2Fopenid.net%2Fspecs%2Fconnect%2F1.0%2Fissuer', 'GET', [], ['HTTPS' => 'on']);
        $response = new Response();
        $this->getIssuerDiscoveryEndpoint()->handle($request, $response);

        $response->getBody()->rewind();

        $this->assertEquals(400, $response->getStatusCode());
        $this->assertEquals('{"error":"invalid_request","error_description":"Unsupported domain.","error_uri":"https:\/\/foo.test\/Error\/BadRequest\/invalid_request"}', $response->getBody()->getContents());
    }

    public function testInvalidResourceFormatInTheRequest()
    {
        $request = $this->createRequest('/?resource=user1&rel=http%3A%2F%2Fopenid.net%2Fspecs%2Fconnect%2F1.0%2Fissuer', 'GET', [], ['HTTPS' => 'on']);
        $response = new Response();
        $this->getIssuerDiscoveryEndpoint()->handle($request, $response);

        $response->getBody()->rewind();

        $this->assertEquals(400, $response->getStatusCode());
        $this->assertEquals('{"error":"invalid_request","error_description":"Unsupported resource value. Must be compliant with RFC3986 (URI) or RFC5322 (e-mail).","error_uri":"https:\/\/foo.test\/Error\/BadRequest\/invalid_request"}', $response->getBody()->getContents());
    }

    public function testDomainForEmailResourceInTheRequest()
    {
        $request = $this->createRequest('/?resource=acct:user1%40my-service.com:9000&rel=http%3A%2F%2Fopenid.net%2Fspecs%2Fconnect%2F1.0%2Fissuer', 'GET', [], ['HTTPS' => 'on']);
        $response = new Response();
        $this->getIssuerDiscoveryEndpoint()->handle($request, $response);

        $response->getBody()->rewind();

        $this->assertEquals(200, $response->getStatusCode());
        $this->assertEquals('{"subject":"acct:user1@my-service.com:9000","links":[{"rel":"http:\/\/openid.net\/specs\/connect\/1.0\/issuer","href":"https:\/\/server.example.com"}]}', $response->getBody()->getContents());
    }

    public function testDomainForUriResourceInTheRequest()
    {
        $request = $this->createRequest('/?resource=https%3A%2F%2Fmy-service.com:9000%2F%2Buser1&rel=http%3A%2F%2Fopenid.net%2Fspecs%2Fconnect%2F1.0%2Fissuer', 'GET', [], ['HTTPS' => 'on']);
        $response = new Response();
        $this->getIssuerDiscoveryEndpoint()->handle($request, $response);

        $response->getBody()->rewind();

        $this->assertEquals(200, $response->getStatusCode());
        $this->assertEquals('{"subject":"https:\/\/my-service.com:9000\/+user1","links":[{"rel":"http:\/\/openid.net\/specs\/connect\/1.0\/issuer","href":"https:\/\/server.example.com"}]}', $response->getBody()->getContents());
    }
}
