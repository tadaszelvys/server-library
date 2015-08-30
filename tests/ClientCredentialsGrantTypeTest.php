<?php

namespace OAuth2\Test;

use OAuth2\Exception\BaseExceptionInterface;
use OAuth2\Exception\ExceptionManagerInterface;
use SpomkyLabs\Service\Jose;

/**
 * @group ClientCredentialsGrantType
 */
class ClientCredentialsGrantTypeTest extends Base
{
    public function testUnsecuredRequest()
    {
        $request = $this->createRequest();

        try {
            $this->getTokenEndpoint()->getAccessToken($request);
            $this->fail('Should throw an Exception');
        } catch (BaseExceptionInterface $e) {
            $this->assertEquals('invalid_request', $e->getMessage());
            $this->assertEquals('The request must be secured.', $e->getDescription());
            $this->assertEquals(400, $e->getHttpCode());
        }
    }

    public function testNotPostMethod()
    {
        $request = $this->createRequest('/', 'GET', [], ['HTTPS' => 'on']);

        try {
            $this->getTokenEndpoint()->getAccessToken($request);
            $this->fail('Should throw an Exception');
        } catch (BaseExceptionInterface $e) {
            $this->assertEquals('invalid_request', $e->getMessage());
            $this->assertEquals('Method must be POST.', $e->getDescription());
            $this->assertEquals(400, $e->getHttpCode());
        }
    }

    public function testGrantTypeIsMissing()
    {
        $request = $this->createRequest('/', 'POST', [], ['HTTPS' => 'on']);

        try {
            $this->getTokenEndpoint()->getAccessToken($request);
            $this->fail('Should throw an Exception');
        } catch (BaseExceptionInterface $e) {
            $this->assertEquals('invalid_request', $e->getMessage());
            $this->assertEquals('The parameter "grant_type" parameter is missing.', $e->getDescription());
            $this->assertEquals(400, $e->getHttpCode());
        }
    }

    public function testUnknownClient()
    {
        $request = $this->createRequest('/', 'POST', [], ['HTTPS' => 'on', 'PHP_AUTH_USER' => 'plic', 'PHP_AUTH_PW' => 'secret'], [], http_build_query(['grant_type' => 'client_credentials']));

        try {
            $this->getTokenEndpoint()->getAccessToken($request);
            $this->fail('Should throw an Exception');
        } catch (BaseExceptionInterface $e) {
            $this->assertEquals('invalid_client', $e->getMessage());
            $this->assertEquals('Unknown client', $e->getDescription());
            $this->assertEquals(401, $e->getHttpCode());
        }
    }

    public function testUnsupportedGrantType()
    {
        $request = $this->createRequest('/', 'POST', [], ['HTTPS' => 'on', 'PHP_AUTH_USER' => 'bar', 'PHP_AUTH_PW' => 'secret'], [], http_build_query(['grant_type' => 'bar']));

        try {
            $this->getTokenEndpoint()->getAccessToken($request);
            $this->fail('Should throw an Exception');
        } catch (BaseExceptionInterface $e) {
            $this->assertEquals('unsupported_grant_type', $e->getMessage());
            $this->assertEquals('The grant type "bar" is not supported by this server', $e->getDescription());
            $this->assertEquals(501, $e->getHttpCode());
        }
    }

    public function testGrantTypeUnauthorizedForClient()
    {
        $request = $this->createRequest('/', 'POST', [], ['HTTPS' => 'on', 'PHP_AUTH_USER' => 'baz', 'PHP_AUTH_PW' => 'secret'], [], http_build_query(['grant_type' => 'client_credentials']));

        try {
            $this->getTokenEndpoint()->getAccessToken($request);
            $this->fail('Should throw an Exception');
        } catch (BaseExceptionInterface $e) {
            $this->assertEquals('unauthorized_client', $e->getMessage());
            $this->assertEquals('The grant type "client_credentials" is unauthorized for this client_id', $e->getDescription());
            $this->assertEquals(400, $e->getHttpCode());
        }
    }

    public function testGrantTypeAuthorizedForClient()
    {
        $request = $this->createRequest('/', 'POST', [], ['HTTPS' => 'on', 'PHP_AUTH_USER' => 'bar', 'PHP_AUTH_PW' => 'secret'], [], http_build_query(['grant_type' => 'client_credentials']));

        $response = $this->getTokenEndpoint()->getAccessToken($request);

        $this->assertEquals('application/json', $response->headers->get('Content-Type'));
        $this->assertEquals('no-store, private', $response->headers->get('Cache-Control'));
        $this->assertEquals(200, $response->getStatusCode());
        $this->assertEquals('no-cache', $response->headers->get('Pragma'));
        $this->assertRegExp('{"access_token":"[^"]+","expires_in":[^"]+,"scope":"scope1 scope2","token_type":"Bearer"}', $response->getContent());
    }

    public function testClientNotConfidential()
    {
        $request = $this->createRequest('/', 'POST', [], ['HTTPS' => 'on'], ['X-OAuth2-Public-Client-ID' => 'foo'], http_build_query(['grant_type' => 'client_credentials']));

        try {
            $this->getTokenEndpoint()->getAccessToken($request);
            $this->fail('Should throw an Exception');
        } catch (BaseExceptionInterface $e) {
            $this->assertEquals('invalid_client', $e->getMessage());
            $this->assertEquals('The client is not a confidential client', $e->getDescription());
            $this->assertEquals(400, $e->getHttpCode());
        }
    }

    public function testGrantTypeAuthorizedForJWTClientButTokenExpired()
    {
        $request = $this->createRequest(
            '/',
            'POST',
            [],
            ['HTTPS' => 'on'],
            [],
            http_build_query(
                [
                    'grant_type' => 'client_credentials',
                    'client_assertion_type' => 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer',
                    'client_assertion' => 'eyJhbGciOiJIUzUxMiIsImtpZCI6IkpXSzIifQ.eyJleHAiOjE0NDA4ODc5NDcsImF1ZCI6Ik15IEF1dGhvcml6YXRpb24gU2VydmVyIiwiaXNzIjoiand0MSJ9.NmJTFCHidy5__R655Io_d_zGoxBhtNIqAgc3KZ4r10tZqMHvclGLwbgpHqEaaOl_f1K2-miyl2KP8Nu3kzdXkg',
                ]
            )
        );

        try {
            $this->getTokenEndpoint()->getAccessToken($request);
        } catch (BaseExceptionInterface $e) {
            $this->assertEquals(ExceptionManagerInterface::INVALID_REQUEST, $e->getMessage());
            $this->assertEquals('The JWT has expired.', $e->getDescription());
        }
    }

    public function testGrantTypeAuthorizedForJWTClientButBadAudience()
    {
        $jose = Jose::getInstance();
        $jws = $jose->sign(
            'JWK2',
            [
                'exp' => time()+3600,
                'aud' => 'Bad Audience',
                'iss' => 'jwt1',
            ],
            [
                'alg' => 'HS512'
            ]
        );

        $request = $this->createRequest(
            '/',
            'POST',
            [],
            ['HTTPS' => 'on'],
            [],
            http_build_query(
                [
                    'grant_type' => 'client_credentials',
                    'client_assertion_type' => 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer',
                    'client_assertion' => $jws,
                ]
            )
        );

        try {
            $this->getTokenEndpoint()->getAccessToken($request);
        } catch (BaseExceptionInterface $e) {
            $this->assertEquals(ExceptionManagerInterface::INVALID_REQUEST, $e->getMessage());
            $this->assertEquals('Bad audience.', $e->getDescription());
        }
    }

    public function testSignedAssertionForJWTClient()
    {
        $jose = Jose::getInstance();
        $jws = $jose->sign(
            'JWK2',
            [
                'exp' => time()+3600,
                'aud' => 'My Authorization Server',
                'iss' => 'jwt1',
            ],
            [
                'alg' => 'HS512'
            ]
        );

        $request = $this->createRequest(
            '/',
            'POST',
            [],
            ['HTTPS' => 'on'],
            [],
            http_build_query(
                [
                    'grant_type' => 'client_credentials',
                    'client_assertion_type' => 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer',
                    'client_assertion' => $jws,
                ]
            )
        );

        $response = $this->getTokenEndpoint()->getAccessToken($request);

        $this->assertEquals('application/json', $response->headers->get('Content-Type'));
        $this->assertEquals('no-store, private', $response->headers->get('Cache-Control'));
        $this->assertEquals(200, $response->getStatusCode());
        $this->assertEquals('no-cache', $response->headers->get('Pragma'));
        $this->assertRegExp('{"access_token":"[^"]+","expires_in":[^"]+,"scope":"scope1 scope2","token_type":"Bearer"}', $response->getContent());
    }

    public function testEncryptedAndSignedAssertionForJWTClient()
    {
        $jose = Jose::getInstance();
        $jws = $jose->signAndEncrypt(
            [
                'exp' => time()+3600,
                'aud' => 'My Authorization Server',
                'iss' => 'jwt1',
            ],
            'JWK2',
            [
                'cty' => 'JWT',
                'alg' => 'HS512',
            ],
            'JWK1',
            [
                'cty' => 'JWT',
                'alg' => 'A256KW',
                'enc' => 'A256CBC-HS512',
                'exp' => time()+3600,
                'aud' => 'My Authorization Server',
                'iss' => 'jwt1',
            ]
        );

        $request = $this->createRequest(
            '/',
            'POST',
            [],
            ['HTTPS' => 'on'],
            [],
            http_build_query(
                [
                    'grant_type' => 'client_credentials',
                    'client_assertion_type' => 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer',
                    'client_assertion' => $jws,
                ]
            )
        );

        $response = $this->getTokenEndpoint()->getAccessToken($request);

        $this->assertEquals('application/json', $response->headers->get('Content-Type'));
        $this->assertEquals('no-store, private', $response->headers->get('Cache-Control'));
        $this->assertEquals(200, $response->getStatusCode());
        $this->assertEquals('no-cache', $response->headers->get('Pragma'));
        $this->assertRegExp('{"access_token":"[^"]+","expires_in":[^"]+,"scope":"scope1 scope2","token_type":"Bearer"}', $response->getContent());
    }
}
