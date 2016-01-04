<?php

/*
 * The MIT License (MIT)
 *
 * Copyright (c) 2014-2015 Spomky-Labs
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file for details.
 */

namespace OAuth2\Test\Functional;

use Jose\JSONSerializationModes;
use Jose\Object\EncryptionInstruction;
use Jose\Object\JWK;
use Jose\Object\SignatureInstruction;
use OAuth2\Exception\BaseException;
use OAuth2\Exception\BaseExceptionInterface;
use OAuth2\Exception\ExceptionManagerInterface;
use OAuth2\Test\Base;
use Zend\Diactoros\Response;

/**
 * @group ClientCredentialsGrantType
 */
class ClientCredentialsGrantTypeTest extends Base
{
    public function testUnsecuredRequest()
    {
        $response = new Response();
        $request = $this->createRequest();

        try {
            $this->getTokenEndpoint()->getAccessToken($request, $response);
            $this->fail('Should throw an Exception');
        } catch (BaseExceptionInterface $e) {
            $this->assertEquals('invalid_request', $e->getMessage());
            $this->assertEquals('The request must be secured.', $e->getDescription());
            $this->assertEquals(400, $e->getHttpCode());
        }
    }

    public function testNotPostMethod()
    {
        $response = new Response();
        $request = $this->createRequest('/', 'GET', [], ['HTTPS' => 'on']);

        try {
            $this->getTokenEndpoint()->getAccessToken($request, $response);
            $this->fail('Should throw an Exception');
        } catch (BaseExceptionInterface $e) {
            $this->assertEquals('invalid_request', $e->getMessage());
            $this->assertEquals('Method must be POST.', $e->getDescription());
            $this->assertEquals(400, $e->getHttpCode());
        }
    }

    public function testGrantTypeIsMissing()
    {
        $response = new Response();
        $request = $this->createRequest('/', 'POST', [], ['HTTPS' => 'on']);

        try {
            $this->getTokenEndpoint()->getAccessToken($request, $response);
            $this->fail('Should throw an Exception');
        } catch (BaseExceptionInterface $e) {
            $this->assertEquals('invalid_request', $e->getMessage());
            $this->assertEquals('The parameter "grant_type" parameter is missing.', $e->getDescription());
            $this->assertEquals(400, $e->getHttpCode());
        }
    }

    public function testUnknownClient()
    {
        $response = new Response();
        $request = $this->createRequest('/', 'POST', ['grant_type' => 'client_credentials'], ['HTTPS' => 'on', 'PHP_AUTH_USER' => 'plic', 'PHP_AUTH_PW' => 'secret']);

        try {
            $this->getTokenEndpoint()->getAccessToken($request, $response);
            $this->fail('Should throw an Exception');
        } catch (BaseExceptionInterface $e) {
            $this->assertEquals('invalid_client', $e->getMessage());
            $this->assertEquals('Client authentication failed.', $e->getDescription());
            $this->assertEquals(401, $e->getHttpCode());
        }
    }

    public function testUnsupportedGrantType()
    {
        $response = new Response();
        $request = $this->createRequest('/', 'POST', ['grant_type' => 'bar'], ['HTTPS' => 'on', 'PHP_AUTH_USER' => 'bar', 'PHP_AUTH_PW' => 'secret']);

        try {
            $this->getTokenEndpoint()->getAccessToken($request, $response);
            $this->fail('Should throw an Exception');
        } catch (BaseExceptionInterface $e) {
            $this->assertEquals('unsupported_grant_type', $e->getMessage());
            $this->assertEquals('The grant type "bar" is not supported by this server', $e->getDescription());
            $this->assertEquals(501, $e->getHttpCode());
        }
    }

    public function testGrantTypeUnauthorizedForClient()
    {
        $response = new Response();
        $request = $this->createRequest('/', 'POST', ['grant_type' => 'client_credentials'], ['HTTPS' => 'on', 'PHP_AUTH_USER' => 'baz', 'PHP_AUTH_PW' => 'secret']);

        try {
            $this->getTokenEndpoint()->getAccessToken($request, $response);
            $this->fail('Should throw an Exception');
        } catch (BaseExceptionInterface $e) {
            $this->assertEquals('unauthorized_client', $e->getMessage());
            $this->assertEquals('The grant type "client_credentials" is unauthorized for this client_id', $e->getDescription());
            $this->assertEquals(400, $e->getHttpCode());
        }
    }

    public function testGrantTypeAuthorizedForClient()
    {
        $response = new Response();
        $request = $this->createRequest('/', 'POST', ['grant_type' => 'client_credentials'], ['HTTPS' => 'on', 'PHP_AUTH_USER' => 'bar', 'PHP_AUTH_PW' => 'secret']);

        $this->getTokenEndpoint()->getAccessToken($request, $response);
        $response->getBody()->rewind();

        $this->assertEquals('application/json', $response->getHeader('Content-Type')[0]);
        $this->assertEquals('no-store, private', $response->getHeader('Cache-Control')[0]);
        $this->assertEquals(200, $response->getStatusCode());
        $this->assertEquals('no-cache', $response->getHeader('Pragma')[0]);
        $this->assertRegExp('{"access_token":"[^"]+","token_type":"Bearer","expires_in":[^"]+,"scope":"scope1 scope2"}', $response->getBody()->getContents());
    }

    public function testGrantTypeAuthorizedForClientWithMacAccessToken()
    {
        $response = new Response();
        $request = $this->createRequest('/', 'POST', ['grant_type' => 'client_credentials'], ['HTTPS' => 'on', 'PHP_AUTH_USER' => 'mac', 'PHP_AUTH_PW' => 'secret']);

        $this->getTokenEndpoint()->getAccessToken($request, $response);
        $response->getBody()->rewind();

        $this->assertEquals('application/json', $response->getHeader('Content-Type')[0]);
        $this->assertEquals('no-store, private', $response->getHeader('Cache-Control')[0]);
        $this->assertEquals(200, $response->getStatusCode());
        $this->assertEquals('no-cache', $response->getHeader('Pragma')[0]);
        $this->assertRegExp('{"access_token":"[^"]+","token_type":"MAC","expires_in":[^"]+,"scope":"scope1 scope2","mac_key":"[^"]+","mac_algorithm":"hmac-sha-256"}', $response->getBody()->getContents());
    }

    public function testGrantTypeAuthorizedForClientUsingBadDigestAuthenticationScheme1()
    {
        $response = new Response();
        $request = $this->createRequest('/', 'POST', ['grant_type' => 'client_credentials'], ['HTTPS' => 'on', 'PHP_AUTH_DIGEST' => '0123456789']);

        try {
            $this->getTokenEndpoint()->getAccessToken($request, $response);
        } catch (BaseException $e) {
            $this->assertEquals('invalid_client', $e->getMessage());
            $this->assertEquals('Missing mandatory digest value(s): username, realm, nonce, uri, response, opaque.', $e->getDescription());
            $this->assertEquals(401, $e->getHttpCode());
            $this->assertTrue(array_key_exists('WWW-Authenticate', $e->getResponseHeaders()));
        }
    }

    public function testGrantTypeAuthorizedForClientUsingBadDigestAuthenticationScheme2()
    {
        $response = new Response();
        $request = $this->createRequest('/', 'POST', ['grant_type' => 'client_credentials'], ['HTTPS' => 'on', 'PHP_AUTH_DIGEST' => $this->createHttpDigestWithBadRealm('POST', '/', 'Mufasa', 'Circle Of Life', 'auth-int', http_build_query(['grant_type' => 'client_credentials']))]);

        try {
            $this->getTokenEndpoint()->getAccessToken($request, $response);
        } catch (BaseException $e) {
            $this->assertEquals('invalid_client', $e->getMessage());
            $this->assertEquals('Response realm name "Foo Bar Service" does not match system realm name of "testrealm@host.com".', $e->getDescription());
            $this->assertEquals(401, $e->getHttpCode());
            $this->assertTrue(array_key_exists('WWW-Authenticate', $e->getResponseHeaders()));
        }
    }

    public function testGrantTypeAuthorizedForClientUsingBadDigestAuthenticationScheme3()
    {
        $response = new Response();
        $request = $this->createRequest('/', 'POST', ['grant_type' => 'client_credentials'], ['HTTPS' => 'on', 'PHP_AUTH_DIGEST' => $this->createHttpDigestWithoutCNonce('POST', '/', 'Mufasa', 'Circle Of Life', 'auth-int', http_build_query(['grant_type' => 'client_credentials']))]);

        try {
            $this->getTokenEndpoint()->getAccessToken($request, $response);
        } catch (BaseException $e) {
            $this->assertEquals('invalid_client', $e->getMessage());
            $this->assertEquals('Missing mandatory digest value "nc" or "cnonce".', $e->getDescription());
            $this->assertEquals(401, $e->getHttpCode());
            $this->assertTrue(array_key_exists('WWW-Authenticate', $e->getResponseHeaders()));
        }
    }

    public function testGrantTypeAuthorizedForClientUsingDigestAuthenticationScheme()
    {
        $response = new Response();
        $request = $this->createRequest('/', 'POST', ['grant_type' => 'client_credentials'], ['HTTPS' => 'on', 'PHP_AUTH_DIGEST' => $this->createValidDigest('POST', '/', 'Mufasa', 'Circle Of Life', 'auth', http_build_query(['grant_type' => 'client_credentials']))]);

        $this->getTokenEndpoint()->getAccessToken($request, $response);
        $response->getBody()->rewind();

        $this->assertEquals('application/json', $response->getHeader('Content-Type')[0]);
        $this->assertEquals('no-store, private', $response->getHeader('Cache-Control')[0]);
        $this->assertEquals(200, $response->getStatusCode());
        $this->assertEquals('no-cache', $response->getHeader('Pragma')[0]);
        $this->assertRegExp('{"access_token":"[^"]+","token_type":"Bearer","expires_in":[^"]+,"scope":"scope1 scope2"}', $response->getBody()->getContents());
    }

    public function testGrantTypeNotAuthorizedForClientUsingDigestAuthenticationScheme()
    {
        $response = new Response();
        $request = $this->createRequest('/', 'POST', ['grant_type' => 'client_credentials'], ['HTTPS' => 'on', 'PHP_AUTH_DIGEST' => $this->createValidDigest('POST', '/', 'Mufasa', 'Bad secret', 'auth-int', http_build_query(['grant_type' => 'client_credentials']))]);

        try {
            $this->getTokenEndpoint()->getAccessToken($request, $response);
            $this->fail('Should throw an Exception');
        } catch (BaseExceptionInterface $e) {
            $this->assertEquals('invalid_client', $e->getMessage());
            $this->assertEquals('Invalid client credentials.', $e->getDescription());
            $this->assertEquals(401, $e->getHttpCode());
            $this->assertTrue(array_key_exists('WWW-Authenticate', $e->getResponseHeaders()));
        }
    }

    public function testGrantTypeAuthorizedForClientUsingAuthorizationHeader()
    {
        $response = new Response();
        $request = $this->createRequest('/', 'POST', ['grant_type' => 'client_credentials'], ['HTTPS' => 'on'], ['Authorization' => 'Basic '.base64_encode('bar:secret')]);

        $this->getTokenEndpoint()->getAccessToken($request, $response);
        $response->getBody()->rewind();

        $this->assertEquals('application/json', $response->getHeader('Content-Type')[0]);
        $this->assertEquals('no-store, private', $response->getHeader('Cache-Control')[0]);
        $this->assertEquals(200, $response->getStatusCode());
        $this->assertEquals('no-cache', $response->getHeader('Pragma')[0]);
        $this->assertRegExp('{"access_token":"[^"]+","token_type":"Bearer","expires_in":[^"]+,"scope":"scope1 scope2"}', $response->getBody()->getContents());
    }

    public function testGrantTypeAuthorizedForClientUsingAuthorizationHeaderButMissingPassword()
    {
        $response = new Response();
        $request = $this->createRequest('/', 'POST', ['grant_type' => 'client_credentials'], ['HTTPS' => 'on'], ['Authorization' => 'Basic '.base64_encode('bar:')]);

        try {
            $this->getTokenEndpoint()->getAccessToken($request, $response);
        } catch (BaseExceptionInterface $e) {
            $this->assertEquals(ExceptionManagerInterface::INVALID_CLIENT, $e->getMessage());
            $this->assertEquals('Client authentication failed.', $e->getDescription());
        }
    }

    public function testGrantTypeAuthorizedForClientUsingAuthorizationHeaderButBadPassword()
    {
        $response = new Response();
        $request = $this->createRequest('/', 'POST', ['grant_type' => 'client_credentials'], ['HTTPS' => 'on'], ['Authorization' => 'Basic '.base64_encode('bar:foo')]);

        try {
            $this->getTokenEndpoint()->getAccessToken($request, $response);
        } catch (BaseExceptionInterface $e) {
            $this->assertEquals(ExceptionManagerInterface::INVALID_CLIENT, $e->getMessage());
            $this->assertEquals('Invalid client credentials.', $e->getDescription());
        }
    }

    public function testGrantTypeAuthorizedForClientUsingQueryRequest()
    {
        $response = new Response();
        $request = $this->createRequest('/', 'POST', ['grant_type' => 'client_credentials', 'client_id' => 'bar', 'client_secret' => 'secret'], ['HTTPS' => 'on']);

        $this->getTokenEndpoint()->getAccessToken($request, $response);
        $response->getBody()->rewind();

        $this->assertEquals('application/json', $response->getHeader('Content-Type')[0]);
        $this->assertEquals('no-store, private', $response->getHeader('Cache-Control')[0]);
        $this->assertEquals(200, $response->getStatusCode());
        $this->assertEquals('no-cache', $response->getHeader('Pragma')[0]);
        $this->assertRegExp('{"access_token":"[^"]+","token_type":"Bearer","expires_in":[^"]+,"scope":"scope1 scope2"}', $response->getBody()->getContents());
    }

    public function testGrantTypeAuthorizedForClientAndJWTAccessToken()
    {
        $response = new Response();
        $request = $this->createRequest('/', 'POST', ['grant_type' => 'client_credentials'], ['HTTPS' => 'on', 'PHP_AUTH_USER' => 'bar', 'PHP_AUTH_PW' => 'secret']);

        $this->getTokenEndpointJWTAccessToken()->getAccessToken($request, $response);
        $response->getBody()->rewind();

        $this->assertEquals('application/json', $response->getHeader('Content-Type')[0]);
        $this->assertEquals('no-store, private', $response->getHeader('Cache-Control')[0]);
        $this->assertEquals(200, $response->getStatusCode());
        $this->assertEquals('no-cache', $response->getHeader('Pragma')[0]);
        $this->assertRegExp('{"access_token":"[^"]+","token_type":"Bearer","expires_in":[^"]+,"scope":"scope1 scope2"}', $response->getBody()->getContents());

        $response->getBody()->rewind();
        $values = json_decode($response->getBody()->getContents(), true);
        $this->assertEquals(5, count(explode('.', $values['access_token'])));

        $access_token = $this->getJWTAccessTokenManager()->getAccessToken($values['access_token']);
        $this->assertInstanceOf('\OAuth2\Token\AccessTokenInterface', $access_token);
        $this->assertEquals('bar', $access_token->getClientPublicId());
        $this->assertEquals('bar', $access_token->getResourceOwnerPublicId());
        $this->assertTrue($access_token->getExpiresIn() <= 3600);
    }

    public function testClientNotConfidential()
    {
        $response = new Response();
        $request = $this->createRequest('/', 'POST', ['grant_type' => 'client_credentials'], ['HTTPS' => 'on'], ['X-OAuth2-Public-Client-ID' => 'foo']);

        try {
            $this->getTokenEndpoint()->getAccessToken($request, $response);
            $this->fail('Should throw an Exception');
        } catch (BaseExceptionInterface $e) {
            $this->assertEquals('invalid_client', $e->getMessage());
            $this->assertEquals('The client is not a confidential client', $e->getDescription());
            $this->assertEquals(400, $e->getHttpCode());
        }
    }

    public function testGrantTypeAuthorizedForJWTClientButTokenExpired()
    {
        $response = new Response();
        $jwk2 = new JWK([
            'kid' => 'JWK2',
            'use' => 'sig',
            'kty' => 'oct',
            'k'   => 'AyM1SysPpbyDfgZld3umj1qzKObwVMkoqQ-EstJQLr_T-1qS0gZH75aKtMN3Yj0iPS4hcgUuTwjAzZr1Z9CAow',
        ]);

        $signature_instruction = new SignatureInstruction(
            $jwk2,
            [
                'kid' => 'JWK2',
                'cty' => 'JWT',
                'alg' => 'HS512',
            ]
        );
        $signer = $this->getSigner(['HS512']);
        $jws = $signer->sign(
            [
                'exp' => time() - 1,
                'aud' => 'My Authorization Server',
                'iss' => 'My JWT issuer',
                'sub' => 'jwt1',
            ],
            [$signature_instruction],
            JSONSerializationModes::JSON_COMPACT_SERIALIZATION
        );

        $request = $this->createRequest(
            '/',
            'POST',
            [
                'grant_type'            => 'client_credentials',
                'client_assertion_type' => 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer',
                'client_assertion'      => $jws,
            ],
            ['HTTPS' => 'on']
        );

        try {
            $this->getTokenEndpoint()->getAccessToken($request, $response);
        } catch (BaseExceptionInterface $e) {
            $this->assertEquals(ExceptionManagerInterface::INVALID_REQUEST, $e->getMessage());
            $this->assertEquals('The JWT has expired.', $e->getDescription());
        }
    }

    public function testGrantTypeAuthorizedForJWTClientButBadAudience()
    {
        $response = new Response();
        $jwk2 = new JWK([
            'kid' => 'JWK2',
            'use' => 'sig',
            'kty' => 'oct',
            'k'   => 'AyM1SysPpbyDfgZld3umj1qzKObwVMkoqQ-EstJQLr_T-1qS0gZH75aKtMN3Yj0iPS4hcgUuTwjAzZr1Z9CAow',
        ]);

        $signature_instruction = new SignatureInstruction(
            $jwk2,
            [
                'kid' => 'JWK2',
                'cty' => 'JWT',
                'alg' => 'HS512',
            ]
        );
        $signer = $this->getSigner(['HS512']);
        $jws = $signer->sign(
            [
                'exp' => time() + 3600,
                'aud' => 'Bad Audience',
                'iss' => 'My JWT issuer',
                'sub' => 'jwt1',
            ],
            [$signature_instruction],
            JSONSerializationModes::JSON_COMPACT_SERIALIZATION
        );

        $request = $this->createRequest(
            '/',
            'POST',
            [
                'grant_type'            => 'client_credentials',
                'client_assertion_type' => 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer',
                'client_assertion'      => $jws,
            ],
            ['HTTPS' => 'on']
        );

        try {
            $this->getTokenEndpoint()->getAccessToken($request, $response);
        } catch (BaseExceptionInterface $e) {
            $this->assertEquals(ExceptionManagerInterface::INVALID_REQUEST, $e->getMessage());
            $this->assertEquals('Bad audience.', $e->getDescription());
        }
    }

    public function testSignedAssertionForJWTClient()
    {
        $response = new Response();
        $jwk2 = new JWK([
            'kid' => 'JWK2',
            'use' => 'sig',
            'kty' => 'oct',
            'k'   => 'AyM1SysPpbyDfgZld3umj1qzKObwVMkoqQ-EstJQLr_T-1qS0gZH75aKtMN3Yj0iPS4hcgUuTwjAzZr1Z9CAow',
        ]);

        $signature_instruction = new SignatureInstruction(
            $jwk2,
            [
                'kid' => 'JWK2',
                'cty' => 'JWT',
                'alg' => 'HS512',
            ]
        );
        $signer = $this->getSigner(['HS512']);
        $jws = $signer->sign(
            [
                'exp' => time() + 3600,
                'aud' => 'My Authorization Server',
                'iss' => 'My JWT issuer',
                'sub' => 'jwt1',
            ],
            [$signature_instruction],
            JSONSerializationModes::JSON_COMPACT_SERIALIZATION
        );

        $request = $this->createRequest(
            '/',
            'POST',
            [
                'grant_type'            => 'client_credentials',
                'client_assertion_type' => 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer',
                'client_assertion'      => $jws,
            ],
            ['HTTPS' => 'on']
        );

        $this->getTokenEndpoint()->getAccessToken($request, $response);
        $response->getBody()->rewind();

        $this->assertEquals('application/json', $response->getHeader('Content-Type')[0]);
        $this->assertEquals('no-store, private', $response->getHeader('Cache-Control')[0]);
        $this->assertEquals(200, $response->getStatusCode());
        $this->assertEquals('no-cache', $response->getHeader('Pragma')[0]);
        $this->assertRegExp('{"access_token":"[^"]+","token_type":"Bearer","expires_in":[^"]+,"scope":"scope1 scope2"}', $response->getBody()->getContents());
    }

    public function testEncryptedAndSignedAssertionForJWTClient()
    {
        $response = new Response();
        $jwk1 = new JWK([
            'kid' => 'JWK1',
            'use' => 'enc',
            'kty' => 'oct',
            'k'   => 'ABEiM0RVZneImaq7zN3u_wABAgMEBQYHCAkKCwwNDg8',
        ]);
        $jwk2 = new JWK([
            'kid' => 'JWK2',
            'use' => 'sig',
            'kty' => 'oct',
            'k'   => 'AyM1SysPpbyDfgZld3umj1qzKObwVMkoqQ-EstJQLr_T-1qS0gZH75aKtMN3Yj0iPS4hcgUuTwjAzZr1Z9CAow',
        ]);

        $signature_instruction = new SignatureInstruction(
            $jwk2,
            [
                'kid' => 'JWK2',
                'cty' => 'JWT',
                'alg' => 'HS512',
            ]
        );
        $signer = $this->getSigner(['HS512']);
        $jws = $signer->sign(
            [
                'exp' => time() + 3600,
                'aud' => 'My Authorization Server',
                'iss' => 'My JWT issuer',
                'sub' => 'jwt1',
            ],
            [$signature_instruction],
            JSONSerializationModes::JSON_COMPACT_SERIALIZATION
        );

        $encryption_instruction = new EncryptionInstruction($jwk1);

        $encrypter = $this->getEncrypter(['A256KW', 'A256CBC-HS512']);
        $jwe = $encrypter->encrypt(
            $jws,
            [$encryption_instruction],
            JSONSerializationModes::JSON_COMPACT_SERIALIZATION,
            [
                'kid' => 'JWK1',
                'cty' => 'JWT',
                'alg' => 'A256KW',
                'enc' => 'A256CBC-HS512',
                'exp' => time() + 3600,
                'aud' => 'My Authorization Server',
                'iss' => 'My JWT issuer',
                'sub' => 'jwt1',
            ]
        );

        $request = $this->createRequest(
            '/',
            'POST',
            [
                'grant_type'            => 'client_credentials',
                'client_assertion_type' => 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer',
                'client_assertion'      => $jwe,
            ],
            ['HTTPS' => 'on']
        );

        $this->getTokenEndpoint()->getAccessToken($request, $response);
        $response->getBody()->rewind();

        $this->assertEquals('application/json', $response->getHeader('Content-Type')[0]);
        $this->assertEquals('no-store, private', $response->getHeader('Cache-Control')[0]);
        $this->assertEquals(200, $response->getStatusCode());
        $this->assertEquals('no-cache', $response->getHeader('Pragma')[0]);
        $this->assertRegExp('{"access_token":"[^"]+","token_type":"Bearer","expires_in":[^"]+,"scope":"scope1 scope2"}', $response->getBody()->getContents());
    }
}
