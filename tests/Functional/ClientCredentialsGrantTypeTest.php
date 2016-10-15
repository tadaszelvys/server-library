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

use Jose\Factory\JWEFactory;
use Jose\Factory\JWSFactory;
use Jose\Object\JWK;
use Jose\Object\JWSInterface;
use OAuth2\Exception\BaseExceptionInterface;
use OAuth2\Exception\ExceptionManagerInterface;
use OAuth2\Test\Base;
use OAuth2\Token\JWTAccessTokenInterface;
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
            $this->assertEquals(ExceptionManagerInterface::INVALID_REQUEST, $e->getMessage());
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
            $this->assertEquals(ExceptionManagerInterface::INVALID_REQUEST, $e->getMessage());
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
            $this->assertEquals(ExceptionManagerInterface::INVALID_REQUEST, $e->getMessage());
            $this->assertEquals('The "grant_type" parameter is missing.', $e->getDescription());
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
            $this->assertEquals(ExceptionManagerInterface::INVALID_CLIENT, $e->getMessage());
            $this->assertEquals('Client authentication failed.', $e->getDescription());
            $this->assertEquals(401, $e->getHttpCode());
        }
    }

    public function testUnsupportedGrantType()
    {
        $response = new Response();
        $request = $this->createRequest('/', 'POST', ['grant_type' => 'bar'], ['HTTPS' => 'on', 'PHP_AUTH_USER' => $this->getClientManager()->getClientByName('Mufasa')->getPublicId(), 'PHP_AUTH_PW' => 'Circle Of Life']);

        try {
            $this->getTokenEndpoint()->getAccessToken($request, $response);
            $this->fail('Should throw an Exception');
        } catch (BaseExceptionInterface $e) {
            $this->assertEquals(ExceptionManagerInterface::INVALID_REQUEST, $e->getMessage());
            $this->assertEquals('The grant type "bar" is not supported by this server.', $e->getDescription());
            $this->assertEquals(400, $e->getHttpCode());
        }
    }

    public function testGrantTypeUnauthorizedForClient()
    {
        $response = new Response();
        $request = $this->createRequest('/', 'POST', ['grant_type' => 'client_credentials'], ['HTTPS' => 'on', 'PHP_AUTH_USER' => $this->getClientManager()->getClientByName('baz')->getPublicId(), 'PHP_AUTH_PW' => 'secret']);

        try {
            $this->getTokenEndpoint()->getAccessToken($request, $response);
            $this->fail('Should throw an Exception');
        } catch (BaseExceptionInterface $e) {
            $this->assertEquals(ExceptionManagerInterface::UNAUTHORIZED_CLIENT, $e->getMessage());
            $this->assertEquals('The grant type "client_credentials" is unauthorized for this client.', $e->getDescription());
            $this->assertEquals(400, $e->getHttpCode());
        }
    }

    public function testGrantTypeAuthorizedForClient()
    {
        $response = new Response();
        $request = $this->createRequest('/', 'POST', ['grant_type' => 'client_credentials'], ['HTTPS' => 'on', 'PHP_AUTH_USER' => $this->getClientManager()->getClientByName('Mufasa')->getPublicId(), 'PHP_AUTH_PW' => 'Circle Of Life']);

        $this->getTokenEndpoint()->getAccessToken($request, $response);
        $response->getBody()->rewind();

        $this->assertEquals('application/json', $response->getHeader('Content-Type')[0]);
        $this->assertEquals('no-store, private', $response->getHeader('Cache-Control')[0]);
        $this->assertEquals(200, $response->getStatusCode());
        $this->assertEquals('no-cache', $response->getHeader('Pragma')[0]);
        $this->assertRegExp('{"access_token":"[^"]+","token_type":"Bearer","expires_in":[0-9]+,"refresh_token":"[^"]+","foo":"bar"}', $response->getBody()->getContents());
    }

    public function testGrantTypeNotAuthorizedForClientWithExpiredCredentials()
    {
        $response = new Response();
        $request = $this->createRequest('/', 'POST', ['grant_type' => 'client_credentials'], ['HTTPS' => 'on', 'PHP_AUTH_USER' => 'expired', 'PHP_AUTH_PW' => 'secret']);

        try {
            $this->getTokenEndpoint()->getAccessToken($request, $response);
            $this->fail('Should throw an Exception');
        } catch (BaseExceptionInterface $e) {
            $this->assertEquals(ExceptionManagerInterface::INVALID_CLIENT, $e->getMessage());
            $this->assertEquals('Client authentication failed.', $e->getDescription());
            $this->assertEquals(401, $e->getHttpCode());
        }
    }

    public function testGrantTypeAuthorizedForClientWithMacAccessToken()
    {
        $response = new Response();
        $request = $this->createRequest('/', 'POST', ['grant_type' => 'client_credentials', 'token_type' => 'MAC'], ['HTTPS' => 'on', 'PHP_AUTH_USER' => $this->getClientManager()->getClientByName('mac')->getPublicId(), 'PHP_AUTH_PW' => 'secret']);

        $this->getTokenEndpoint()->getAccessToken($request, $response);
        $response->getBody()->rewind();
        $content = $response->getBody()->getContents();

        $this->assertEquals('application/json', $response->getHeader('Content-Type')[0]);
        $this->assertEquals('no-store, private', $response->getHeader('Cache-Control')[0]);
        $this->assertEquals(200, $response->getStatusCode());
        $this->assertEquals('no-cache', $response->getHeader('Pragma')[0]);
        $this->assertRegExp('{"access_token":"[^"]+","token_type":"MAC","expires_in":[0-9]+,"refresh_token":"[^"]+","mac_key":"[^"]+","mac_algorithm":"hmac-sha-256","foo":"bar"}', $content);
    }

    public function testTokenTypeNotAuthorizedForClient()
    {
        $response = new Response();
        $request = $this->createRequest('/', 'POST', ['grant_type' => 'client_credentials', 'token_type' => 'Bearer'], ['HTTPS' => 'on', 'PHP_AUTH_USER' => $this->getClientManager()->getClientByName('mac')->getPublicId(), 'PHP_AUTH_PW' => 'secret']);

        try {
            $this->getTokenEndpoint()->getAccessToken($request, $response);
            $this->fail('Should throw an Exception');
        } catch (BaseExceptionInterface $e) {
            $this->assertEquals(ExceptionManagerInterface::INVALID_REQUEST, $e->getMessage());
            $this->assertEquals('The token type "Bearer" is not allowed for the client.', $e->getDescription());
            $this->assertEquals(400, $e->getHttpCode());
        }
    }

    public function testGrantTypeAuthorizedForClientUsingAuthorizationHeader()
    {
        $response = new Response();
        $request = $this->createRequest('/', 'POST', ['grant_type' => 'client_credentials'], ['HTTPS' => 'on'], ['Authorization' => 'Basic '.base64_encode($this->getClientManager()->getClientByName('Mufasa')->getPublicId().':Circle Of Life')]);

        $this->getTokenEndpoint()->getAccessToken($request, $response);
        $response->getBody()->rewind();

        $this->assertEquals('application/json', $response->getHeader('Content-Type')[0]);
        $this->assertEquals('no-store, private', $response->getHeader('Cache-Control')[0]);
        $this->assertEquals(200, $response->getStatusCode());
        $this->assertEquals('no-cache', $response->getHeader('Pragma')[0]);
        $this->assertRegExp('{"access_token":"[^"]+","token_type":"Bearer","expires_in":[0-9]+,"refresh_token":"[^"]+","foo":"bar"}', $response->getBody()->getContents());
    }

    public function testGrantTypeAuthorizedForClientUsingAuthorizationHeaderButMissingPassword()
    {
        $response = new Response();
        $request = $this->createRequest('/', 'POST', ['grant_type' => 'client_credentials'], ['HTTPS' => 'on'], ['Authorization' => 'Basic '.base64_encode($this->getClientManager()->getClientByName('bar')->getPublicId().':')]);

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
        $request = $this->createRequest('/', 'POST', ['grant_type' => 'client_credentials'], ['HTTPS' => 'on'], ['Authorization' => 'Basic '.base64_encode($this->getClientManager()->getClientByName('Mufasa')->getPublicId().':foo')]);

        try {
            $this->getTokenEndpoint()->getAccessToken($request, $response);
        } catch (BaseExceptionInterface $e) {
            $this->assertEquals(ExceptionManagerInterface::INVALID_CLIENT, $e->getMessage());
            $this->assertEquals('Client authentication failed.', $e->getDescription());
        }
    }

    public function testGrantTypeAuthorizedForClientUsingQueryRequest()
    {
        $response = new Response();
        $request = $this->createRequest('/', 'POST', ['grant_type' => 'client_credentials', 'client_id' => $this->getClientManager()->getClientByName('Mufasa2')->getPublicId(), 'client_secret' => 'Circle Of Life'], ['HTTPS' => 'on']);

        $this->getTokenEndpoint()->getAccessToken($request, $response);
        $response->getBody()->rewind();

        $this->assertEquals('application/json', $response->getHeader('Content-Type')[0]);
        $this->assertEquals('no-store, private', $response->getHeader('Cache-Control')[0]);
        $this->assertEquals(200, $response->getStatusCode());
        $this->assertEquals('no-cache', $response->getHeader('Pragma')[0]);
        $this->assertRegExp('{"access_token":"[^"]+","token_type":"Bearer","expires_in":[0-9]+,"refresh_token":"[^"]+","foo":"bar"}', $response->getBody()->getContents());
    }

    public function testGrantTypeAuthorizedForClientAndJWTAccessToken()
    {
        $response = new Response();
        $request = $this->createRequest('/', 'POST', ['grant_type' => 'client_credentials'], ['HTTPS' => 'on', 'PHP_AUTH_USER' => $this->getClientManager()->getClientByName('Mufasa')->getPublicId(), 'PHP_AUTH_PW' => 'Circle Of Life']);

        $this->getTokenEndpoint()->getAccessToken($request, $response);
        $response->getBody()->rewind();
        $content = $response->getBody()->getContents();

        $this->assertEquals('application/json', $response->getHeader('Content-Type')[0]);
        $this->assertEquals('no-store, private', $response->getHeader('Cache-Control')[0]);
        $this->assertEquals(200, $response->getStatusCode());
        $this->assertEquals('no-cache', $response->getHeader('Pragma')[0]);
        $this->assertRegExp('{"access_token":"[^"]+","token_type":"Bearer","expires_in":[0-9^"]+,"refresh_token":"[^"]+","foo":"bar"}', $content);

        $response->getBody()->rewind();
        $values = json_decode($content, true);
        $this->assertEquals(5, count(explode('.', $values['access_token'])));

        $access_token = $this->getJWTAccessTokenManager()->getAccessToken($values['access_token']);
        $this->assertInstanceOf(JWTAccessTokenInterface::class, $access_token);
        $this->assertEquals($this->getClientManager()->getClientByName('Mufasa')->getPublicId(), $access_token->getClientPublicId());
        $this->assertEquals($this->getClientManager()->getClientByName('Mufasa')->getPublicId(), $access_token->getResourceOwnerPublicId());
        $this->assertInstanceOf(JWSInterface::class, $access_token->getJWS());
        $this->assertTrue($access_token->getExpiresIn() <= 3600);
    }

    public function testClientNotConfidential()
    {
        $response = new Response();
        $request = $this->createRequest('/', 'POST', ['grant_type' => 'client_credentials'], ['HTTPS' => 'on'], ['X-OAuth2-Public-Client-ID' => $this->getClientManager()->getClientByName('foo')->getPublicId()]);

        try {
            $this->getTokenEndpoint()->getAccessToken($request, $response);
            $this->fail('Should throw an Exception');
        } catch (BaseExceptionInterface $e) {
            $this->assertEquals(ExceptionManagerInterface::INVALID_CLIENT, $e->getMessage());
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

        $jws = JWSFactory::createJWSToCompactJSON([
                'jti' => '0123456789',
                'exp' => time() - 1,
                'aud' => $this->getIssuer(),
                'iss' => $this->getClientManager()->getClientByName('jwt1')->getPublicId(),
                'sub' => $this->getClientManager()->getClientByName('jwt1')->getPublicId(),
            ],
            $jwk2,
            [
                'kid' => 'JWK2',
                'cty' => 'JWT',
                'alg' => 'HS512',
            ]
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
            $this->assertEquals(ExceptionManagerInterface::INVALID_CLIENT, $e->getMessage());
            $this->assertEquals('Client authentication failed.', $e->getDescription());
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

        $jws = JWSFactory::createJWSToCompactJSON([
                'jti' => '0123456789',
                'exp' => time() + 3600,
                'aud' => 'Bad Audience',
                'iss' => $this->getClientManager()->getClientByName('jwt1')->getPublicId(),
                'sub' => $this->getClientManager()->getClientByName('jwt1')->getPublicId(),
            ],
            $jwk2,
            [
                'kid' => 'JWK2',
                'cty' => 'JWT',
                'alg' => 'HS512',
            ]
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
            $this->assertEquals(ExceptionManagerInterface::INVALID_CLIENT, $e->getMessage());
            $this->assertEquals('Client authentication failed.', $e->getDescription());
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

        $jws = JWSFactory::createJWSToCompactJSON([
                'jti' => '0123456789',
                'exp' => time() + 3600,
                'aud' => $this->getIssuer(),
                'iss' => $this->getClientManager()->getClientByName('jwt1')->getPublicId(),
                'sub' => $this->getClientManager()->getClientByName('jwt1')->getPublicId(),
            ],
            $jwk2,
            [
                'kid' => 'JWK2',
                'cty' => 'JWT',
                'alg' => 'HS512',
            ]
        );

        $request = $this->createRequest(
            '/',
            'POST',
            [
                'grant_type'            => 'client_credentials',
                'client_assertion_type' => 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer',
                'client_assertion'      => $jws,
                'scope'                 => 'scope1',
            ],
            ['HTTPS' => 'on']
        );

        $this->getTokenEndpoint()->getAccessToken($request, $response);
        $response->getBody()->rewind();

        $this->assertEquals('application/json', $response->getHeader('Content-Type')[0]);
        $this->assertEquals('no-store, private', $response->getHeader('Cache-Control')[0]);
        $this->assertEquals(200, $response->getStatusCode());
        $this->assertEquals('no-cache', $response->getHeader('Pragma')[0]);
        $this->assertRegExp('{"access_token":"[^"]+","token_type":"Bearer","scope":"scope1","refresh_token":"[^"]+","foo":"bar"}', $response->getBody()->getContents());
    }

    public function testMissingClaim()
    {
        $response = new Response();
        $jwk2 = new JWK([
            'kid' => 'JWK2',
            'use' => 'sig',
            'kty' => 'oct',
            'k'   => 'AyM1SysPpbyDfgZld3umj1qzKObwVMkoqQ-EstJQLr_T-1qS0gZH75aKtMN3Yj0iPS4hcgUuTwjAzZr1Z9CAow',
        ]);

        $jws = JWSFactory::createJWSToCompactJSON([
                'exp' => time() + 3600,
                'aud' => $this->getIssuer(),
                'iss' => $this->getClientManager()->getClientByName('jwt1')->getPublicId(),
                'sub' => $this->getClientManager()->getClientByName('jwt1')->getPublicId(),
            ],
            $jwk2,
            [
                'kid' => 'JWK2',
                'cty' => 'JWT',
                'alg' => 'HS512',
            ]
        );

        $request = $this->createRequest(
            '/',
            'POST',
            [
                'grant_type'            => 'client_credentials',
                'client_assertion_type' => 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer',
                'client_assertion'      => $jws,
                'scope'                 => 'scope1',
            ],
            ['HTTPS' => 'on']
        );

        try {
            $this->getTokenEndpoint()->getAccessToken($request, $response);
        } catch (BaseExceptionInterface $e) {
            $this->assertEquals(ExceptionManagerInterface::INVALID_REQUEST, $e->getMessage());
            $this->assertEquals('The following claim(s) is/are mandatory: "["jti"]".', $e->getDescription());
        }
    }

    public function testSignedAssertionForPasswordClientWithJWTBearerAuthentication()
    {
        $response = new Response();
        $jwk2 = new JWK([
            'kid' => 'PasswordClientBarSecret',
            'use' => 'sig',
            'kty' => 'oct',
            'k'   => 'secret',
        ]);

        $jws = JWSFactory::createJWSToCompactJSON([
                'jti' => '0123456789',
                'exp' => time() + 3600,
                'aud' => $this->getIssuer(),
                'iss' => $this->getClientManager()->getClientByName('bar')->getPublicId(),
                'sub' => $this->getClientManager()->getClientByName('bar')->getPublicId(),
            ],
            $jwk2,
            [
                'kid' => 'JWK2',
                'cty' => 'JWT',
                'alg' => 'HS512',
            ]
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
        $this->assertRegExp('{"access_token":"[^"]+","token_type":"Bearer","expires_in":[0-9]+,"refresh_token":"[^"]+","foo":"bar"}', $response->getBody()->getContents());
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

        $jws = JWSFactory::createJWSToCompactJSON([
                'jti' => '0123456789',
                'exp' => time() + 3600,
                'aud' => $this->getIssuer(),
                'iss' => $this->getClientManager()->getClientByName('jwt1')->getPublicId(),
                'sub' => $this->getClientManager()->getClientByName('jwt1')->getPublicId(),
            ],
            $jwk2,
            [
                'kid' => 'JWK2',
                'cty' => 'JWT',
                'alg' => 'HS512',
            ]
        );

        $jwe = JWEFactory::createJWEToCompactJSON(
            $jws,
            $jwk1,
            [
                'kid' => 'JWK1',
                'cty' => 'JWT',
                'alg' => 'A256KW',
                'enc' => 'A256CBC-HS512',
                'exp' => time() + 3600,
                'aud' => $this->getIssuer(),
                'iss' => $this->getClientManager()->getClientByName('jwt1')->getPublicId(),
                'sub' => $this->getClientManager()->getClientByName('jwt1')->getPublicId(),
            ]
        );

        $request = $this->createRequest(
            '/',
            'POST',
            [
                'grant_type'            => 'client_credentials',
                'client_assertion_type' => 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer',
                'client_assertion'      => $jwe,
                'scope'                 => 'scope1',
            ],
            ['HTTPS' => 'on']
        );

        $this->getTokenEndpoint()->getAccessToken($request, $response);
        $response->getBody()->rewind();

        $this->assertEquals('application/json', $response->getHeader('Content-Type')[0]);
        $this->assertEquals('no-store, private', $response->getHeader('Cache-Control')[0]);
        $this->assertEquals(200, $response->getStatusCode());
        $this->assertEquals('no-cache', $response->getHeader('Pragma')[0]);

        $content = $response->getBody()->getContents();
        $this->assertRegExp('{"access_token":"[^"]+","token_type":"Bearer","scope":"scope1","refresh_token":"[^"]+","foo":"bar"}', $content);
    }

    public function testNoScopeRequestedForErrorPolicy()
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

        $jws = JWSFactory::createJWSToCompactJSON([
                'jti' => '0123456789',
                'exp' => time() + 3600,
                'aud' => $this->getIssuer(),
                'iss' => $this->getClientManager()->getClientByName('jwt1')->getPublicId(),
                'sub' => $this->getClientManager()->getClientByName('jwt1')->getPublicId(),
            ],
            $jwk2,
            [
                'kid' => 'JWK2',
                'cty' => 'JWT',
                'alg' => 'HS512',
            ]
        );

        $jwe = JWEFactory::createJWEToCompactJSON(
            $jws,
            $jwk1,
            [
                'kid' => 'JWK1',
                'cty' => 'JWT',
                'alg' => 'A256KW',
                'enc' => 'A256CBC-HS512',
                'exp' => time() + 3600,
                'aud' => $this->getIssuer(),
                'iss' => $this->getClientManager()->getClientByName('jwt1')->getPublicId(),
                'sub' => $this->getClientManager()->getClientByName('jwt1')->getPublicId(),
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

        try {
            $this->getTokenEndpoint()->getAccessToken($request, $response);
            $this->fail('Should throw an Exception');
        } catch (BaseExceptionInterface $e) {
            $this->assertEquals(ExceptionManagerInterface::INVALID_SCOPE, $e->getMessage());
            $this->assertEquals('No scope was requested.', $e->getDescription());
            $this->assertEquals(400, $e->getHttpCode());
        }
    }
}
