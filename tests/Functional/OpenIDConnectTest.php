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

use Jose\Decrypter;
use Jose\Loader;
use Jose\Object\JWEInterface;
use Jose\Object\JWK;
use Jose\Object\JWSInterface;
use OAuth2\Exception\AuthenticateExceptionInterface;
use OAuth2\Exception\BadRequestExceptionInterface;
use OAuth2\Exception\BaseException;
use OAuth2\OpenIdConnect\Metadata;
use OAuth2\OpenIdConnect\Pairwise\EncryptedSubjectIdentifier;
use OAuth2\OpenIdConnect\Pairwise\HashedSubjectIdentifier;
use OAuth2\Test\Base;
use OAuth2\Token\AccessTokenInterface;
use Zend\Diactoros\Response;
use Zend\Diactoros\ServerRequest;
use Zend\Diactoros\Uri;

/**
 * @group OpenIdConnect
 */
class OpenIDConnectTest extends Base
{
    public function testAuthorizationCodeSuccessWithIdToken()
    {
        $request = new ServerRequest();
        $request = $request->withQueryParams([
            'redirect_uri'          => 'http://example.com/test?good=false',
            'client_id'             => 'Mufasa',
            'response_type'         => 'code',
            'scope'                 => 'openid',
            'nonce'                 => 'foo/bar',
            'state'                 => '0123456789',
            'code_challenge'        => 'E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM',
            'code_challenge_method' => 'plain',
        ]);
        $authorization = $this->getAuthorizationFactory()->createFromRequest(
            $request,
            $this->getUserManager()->getUser('user1'),
            true
        );

        $response = new Response();
        $this->getAuthorizationEndpoint()->authorize($authorization, $response);
        $this->assertRegExp('/^http:\/\/example.com\/test\?good=false&code=[^"]+&state=0123456789#$/', $response->getHeader('Location')[0]);

        $uri = new Uri($response->getHeader('Location')[0]);
        parse_str($uri->getQuery(), $result);
        $authcode = $this->getAuthCodeManager()->getAuthCode($result['code']);

        $this->assertTrue($authcode->getExpiresAt() <= time() + 100);
        $this->assertEquals('Mufasa', $authcode->getClientPublicId());

        $response = new Response();
        $request = $this->createRequest('/', 'POST', ['grant_type' => 'authorization_code', 'client_id' => 'foo', 'redirect_uri' => 'http://example.com/test?good=false', 'code' => $authcode->getToken(), 'code_verifier' => 'E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM'], ['HTTPS' => 'on', 'PHP_AUTH_USER' => 'Mufasa', 'PHP_AUTH_PW' => 'Circle Of Life']);

        $this->getTokenEndpoint()->getAccessToken($request, $response);
        $response->getBody()->rewind();

        $this->assertEquals('application/json', $response->getHeader('Content-Type')[0]);
        $this->assertEquals('no-store, private', $response->getHeader('Cache-Control')[0]);
        $this->assertEquals(200, $response->getStatusCode());
        $this->assertEquals('no-cache', $response->getHeader('Pragma')[0]);
        $this->assertRegExp('{"access_token":"[^"]+","token_type":"Bearer","expires_in":[0-9]+,"scope":"openid","foo":"bar","id_token":"[^"]+"}', $response->getBody()->getContents());

        $response->getBody()->rewind();
        $json = json_decode($response->getBody()->getContents(), true);

        $loader = new Loader();
        $id_token = $loader->load($json['id_token']);

        $this->assertInstanceOf(JWSInterface::class, $id_token);

        $this->assertEquals(
            [
                'code',
                'token',
                'none',
                'id_token',
                'code id_token',
                'id_token token',
                'code id_token token',

            ],
            $this->getAuthorizationEndpoint()->getResponseTypesSupported()
        );

        $this->assertTrue($id_token->hasClaim('iss'));
        $this->assertTrue($id_token->hasClaim('sub'));
        $this->assertEquals('iu6KK2l_kPf4_mOdpWE668f9bc6fk-2auRRZi4lWhi_zpypYTW45N6SpsahXSqbzQNjcbd30f8srPLf7XEdCKA', $id_token->getClaim('sub'));
        $this->assertTrue($id_token->hasClaim('aud'));
        $this->assertTrue($id_token->hasClaim('exp'));
        $this->assertTrue($id_token->hasClaim('iat'));

        $this->assertTrue($id_token->hasClaim('nonce'));
        $this->assertTrue($id_token->hasClaim('nbf'));
        $this->assertTrue($id_token->hasClaim('amr'));
        $this->assertFalse($id_token->hasClaim('acr'));
        $this->assertTrue($id_token->hasClaim('auth_time'));
        $this->assertTrue($id_token->hasClaim('at_hash'));
        $this->assertTrue($id_token->hasClaim('c_hash'));

        $this->assertEquals($this->getIssuer(), $id_token->getClaim('iss'));
        $this->assertEquals('Mufasa', $id_token->getClaim('aud'));
        $this->assertEquals('foo/bar', $id_token->getClaim('nonce'));

        $this->assertEquals('iu6KK2l_kPf4_mOdpWE668f9bc6fk-2auRRZi4lWhi_zpypYTW45N6SpsahXSqbzQNjcbd30f8srPLf7XEdCKA', $id_token->getClaim('sub'));

        $access_token = $this->getJWTAccessTokenManager()->getAccessToken($json['access_token']);
        $this->assertEquals('Mufasa', $access_token->getClientPublicId());
        $this->assertEquals('user1', $access_token->getResourceOwnerPublicId());

        $userinfo = $this->getUserInfoEndpoint()->handle($access_token);
        $userinfo = $loader->load($userinfo);

        $this->assertEquals($userinfo->getClaim('sub'), $id_token->getClaim('sub'));
        $this->assertEquals($userinfo->getClaim('exp'), $id_token->getClaim('exp'));
        $this->assertEquals($userinfo->getClaim('iss'), $id_token->getClaim('iss'));
        $this->assertEquals($userinfo->getClaim('aud'), $id_token->getClaim('aud'));
    }

    public function testHashedPairwise()
    {
        $user = $this->getUserManager()->getUser('user1');
        $algorithm = new HashedSubjectIdentifier($this->getPairwiseKey(), 'sha512', $this->getPairwiseAdditionalData());

        $this->assertEquals(
            'iu6KK2l_kPf4_mOdpWE668f9bc6fk-2auRRZi4lWhi_zpypYTW45N6SpsahXSqbzQNjcbd30f8srPLf7XEdCKA',
            $algorithm->calculateSubjectIdentifier(
                $user,
                'example.com'
            )
        );
    }

    public function testEncryptedPairwise()
    {
        $user = $this->getUserManager()->getUser('user1');
        $algorithm = new EncryptedSubjectIdentifier($this->getPairwiseKey(), 'aes-128-cbc', $this->getPairwiseAdditionalData(), $this->getPairwiseAdditionalData());

        $this->assertEquals(
            'uy1climA7Ruoi3HKyb5vrgygYnO2uL6Wp7xxT1FuYjGRr52Dqqv1Kk27M-gGrrAH',
            $algorithm->calculateSubjectIdentifier(
                $user,
                'example.com'
            )
        );
    }

    public function testCodeTokenSuccess()
    {
        $request = new ServerRequest();
        $request = $request->withQueryParams([
            'redirect_uri'          => 'http://example.com/test?good=false',
            'client_id'             => 'foo',
            'response_type'         => 'code token',
            'code_challenge'        => 'E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM',
            'code_challenge_method' => 'plain',
            'state'                 => 'ABCDEF',
            'scope'                 => 'openid',
            'nonce'                 => '0123456789',
        ]);
        $authorization = $this->getAuthorizationFactory()->createFromRequest(
            $request,
            $this->getUserManager()->getUser('user1'),
            true
        );

        $response = new Response();
        $this->getAuthorizationEndpoint()->authorize($authorization, $response);
        $this->assertRegExp('/^http:\/\/example.com\/test\?good=false#code=[^"]+&access_token=[^"]+&token_type=Bearer&expires_in=[\d]+&scope=openid&foo=bar&state=ABCDEF$/', $response->getHeader('Location')[0]);
        $values = parse_url($response->getHeader('Location')[0]);
        parse_str($values['fragment'], $params);

        $response = new Response();
        $request = $this->createRequest('/', 'POST', ['client_id' => 'foo', 'grant_type' => 'authorization_code', 'code' => $params['code'], 'redirect_uri' => 'http://example.com/test?good=false', 'code_verifier' => 'E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM'], ['HTTPS' => 'on'], ['X-OAuth2-Public-Client-ID' => 'foo']);

        $this->getTokenEndpoint()->getAccessToken($request, $response);
        $response->getBody()->rewind();

        $this->assertEquals('application/json', $response->getHeader('Content-Type')[0]);
        $this->assertEquals('no-store, private', $response->getHeader('Cache-Control')[0]);
        $this->assertEquals(200, $response->getStatusCode());
        $this->assertEquals('no-cache', $response->getHeader('Pragma')[0]);
        $this->assertRegExp('/^{"access_token":"[^"]+","token_type":"Bearer","expires_in":[\d]+,"scope":"openid","foo":"bar","id_token":"[^"]+"}$/', $response->getBody()->getContents());

        $response->getBody()->rewind();
        $json = json_decode($response->getBody()->getContents(), true);

        $access_token = $this->getJWTAccessTokenManager()->getAccessToken($json['access_token']);

        $this->assertInstanceOf(AccessTokenInterface::class, $access_token);
        $this->assertTrue($this->getJWTAccessTokenManager()->isAccessTokenValid($access_token));

        $introspection_request = $this->createRequest('/', 'POST', ['token' => $json['access_token']], ['HTTPS' => 'on'], ['X-OAuth2-Public-Client-ID' => 'foo']);

        $introspection_response = new Response();
        $this->getTokenIntrospectionEndpoint()->introspection($introspection_request, $introspection_response);
        $introspection_response->getBody()->rewind();

        $this->assertEquals(200, $introspection_response->getStatusCode());
        $this->assertRegExp('/^{"active":true,"client_id":"foo","token_type":"Bearer","exp":[\d]+,"sub":"user1","scope":\["openid"\],"jti":"[^"]+","iat":[\d]+,"nbf":[\d]+,"aud":"[^"]+","iss":"[^"]+"}$/', $introspection_response->getBody()->getContents());
    }

    public function testIdTokenSuccess()
    {
        $request = new ServerRequest();
        $request = $request->withQueryParams([
            'redirect_uri'          => 'http://example.com/test?good=false',
            'client_id'             => 'foo',
            'response_type'         => 'id_token',
            'nonce'                 => '0123456789',
            'state'                 => 'ABCDEF',
            'scope'                 => 'openid',
        ]);
        $authorization = $this->getAuthorizationFactory()->createFromRequest(
            $request,
            $this->getUserManager()->getUser('user1'),
            true
        );

        $response = new Response();
        $this->getAuthorizationEndpoint()->authorize($authorization, $response);
        $this->assertRegExp('/^http:\/\/example.com\/test\?good=false#state=ABCDEF&id_token=[^"]+$/', $response->getHeader('Location')[0]);
        $values = parse_url($response->getHeader('Location')[0]);
        parse_str($values['fragment'], $params);

        $loader = new Loader();
        $id_token = $loader->load($params['id_token']);

        $this->assertInstanceOf(JWSInterface::class, $id_token);
        $this->assertTrue($id_token->hasClaim('nonce'));
        $this->assertEquals('0123456789', $id_token->getClaim('nonce'));
    }

    public function testIdTokenSuccessWithEncryptionSupport()
    {
        $request = new ServerRequest();
        $request = $request->withQueryParams([
            'redirect_uri'          => 'http://example.com/test?good=false',
            'client_id'             => 'jwt1',
            'response_type'         => 'id_token',
            'nonce'                 => '0123456789',
            'state'                 => 'ABCDEF',
            'scope'                 => 'openid',
        ]);
        $authorization = $this->getAuthorizationFactory()->createFromRequest(
            $request,
            $this->getUserManager()->getUser('user1'),
            true
        );

        $response = new Response();
        $this->getAuthorizationEndpoint()->authorize($authorization, $response);
        $this->assertRegExp('/^http:\/\/example.com\/test\?good=false#state=ABCDEF&id_token=[^"]+$/', $response->getHeader('Location')[0]);
        $values = parse_url($response->getHeader('Location')[0]);
        parse_str($values['fragment'], $params);

        $loader = new Loader();
        $id_token = $loader->load($params['id_token']);

        $this->assertInstanceOf(JWEInterface::class, $id_token);
        $decrypter = new Decrypter(['A256KW'], ['A256CBC-HS512'], []);
        $decrypter->decryptUsingKey($id_token, new JWK([
            'kid' => 'JWK1',
            'use' => 'enc',
            'kty' => 'oct',
            'k'   => 'ABEiM0RVZneImaq7zN3u_wABAgMEBQYHCAkKCwwNDg8',
        ]));
        $id_token = $loader->load($id_token->getPayload());

        $this->assertTrue($id_token->hasClaim('nonce'));
        $this->assertEquals('0123456789', $id_token->getClaim('nonce'));
    }

    public function testIdTokenTokenSuccess()
    {
        $request = new ServerRequest();
        $request = $request->withQueryParams([
            'redirect_uri'          => 'http://example.com/test?good=false',
            'client_id'             => 'foo',
            'response_type'         => 'id_token token',
            'nonce'                 => '0123456789',
            'state'                 => 'ABCDEF',
            'scope'                 => 'openid',
            'code_challenge'        => 'E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM',
            'code_challenge_method' => 'plain',
        ]);
        $authorization = $this->getAuthorizationFactory()->createFromRequest(
            $request,
            $this->getUserManager()->getUser('user1'),
            true
        );

        $response = new Response();
        $this->getAuthorizationEndpoint()->authorize($authorization, $response);
        $this->assertRegExp('/^http:\/\/example.com\/test\?good=false#access_token=[^"]+&token_type=Bearer&expires_in=[\d]+&scope=openid&foo=bar&state=ABCDEF&id_token=[^"]+$/', $response->getHeader('Location')[0]);
        $values = parse_url($response->getHeader('Location')[0]);
        parse_str($values['fragment'], $params);

        $loader = new Loader();
        $id_token = $loader->load($params['id_token']);

        $this->assertInstanceOf(JWSInterface::class, $id_token);
        $this->assertTrue($id_token->hasClaim('nonce'));
        $this->assertEquals('0123456789', $id_token->getClaim('nonce'));
        $this->assertTrue($id_token->hasClaim('at_hash'));
    }

    public function testCodeIdTokenTokenSuccess()
    {
        $request = new ServerRequest();
        $request = $request->withQueryParams([
            'redirect_uri'          => 'http://example.com/test?good=false',
            'client_id'             => 'foo',
            'response_type'         => 'code id_token token',
            'state'                 => 'ABCDEF',
            'scope'                 => 'openid',
            'nonce'                 => '0123456789',
            'code_challenge'        => 'E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM',
            'code_challenge_method' => 'plain',
        ]);
        $authorization = $this->getAuthorizationFactory()->createFromRequest(
            $request,
            $this->getUserManager()->getUser('user1'),
            true
        );

        $response = new Response();
        $this->getAuthorizationEndpoint()->authorize($authorization, $response);
        $this->assertRegExp('/^http:\/\/example.com\/test\?good=false#code=[^"]+&access_token=[^"]+&token_type=Bearer&expires_in=[\d]+&scope=openid&foo=bar&state=ABCDEF&id_token=[^"]+$/', $response->getHeader('Location')[0]);
        $values = parse_url($response->getHeader('Location')[0]);
        parse_str($values['fragment'], $params);

        $loader = new Loader();
        $id_token = $loader->load($params['id_token']);

        $this->assertInstanceOf(JWSInterface::class, $id_token);
        $this->assertTrue($id_token->hasClaim('nonce'));
        $this->assertEquals('0123456789', $id_token->getClaim('nonce'));
        $this->assertTrue($id_token->hasClaim('at_hash'));
        $this->assertTrue($id_token->hasClaim('c_hash'));

        $response = new Response();
        $request = $this->createRequest('/', 'POST', ['client_id' => 'foo', 'grant_type' => 'authorization_code', 'code' => $params['code'], 'redirect_uri' => 'http://example.com/test?good=false', 'code_verifier' => 'E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM'], ['HTTPS' => 'on'], ['X-OAuth2-Public-Client-ID' => 'foo']);

        $this->getTokenEndpoint()->getAccessToken($request, $response);
        $response->getBody()->rewind();

        $this->assertEquals('application/json', $response->getHeader('Content-Type')[0]);
        $this->assertEquals('no-store, private', $response->getHeader('Cache-Control')[0]);
        $this->assertEquals(200, $response->getStatusCode());
        $this->assertEquals('no-cache', $response->getHeader('Pragma')[0]);
        $this->assertRegExp('{"access_token":"[^"]+","token_type":"Bearer","expires_in":[\d]+,"scope":"openid","foo":"bar","id_token":"[^"]+"}', $response->getBody()->getContents());

        $response->getBody()->rewind();
        $json = json_decode($response->getBody()->getContents(), true);

        $access_token = $this->getJWTAccessTokenManager()->getAccessToken($json['access_token']);

        $this->assertInstanceOf(AccessTokenInterface::class, $access_token);
        $this->assertTrue($this->getJWTAccessTokenManager()->isAccessTokenValid($access_token));

        $loader = new Loader();
        $id_token2 = $loader->load($json['id_token']);

        $this->assertInstanceOf(JWSInterface::class, $id_token2);
        $this->assertTrue($id_token2->hasClaim('nonce'));
        $this->assertEquals('0123456789', $id_token2->getClaim('nonce'));
        $this->assertTrue($id_token2->hasClaim('at_hash'));
        $this->assertTrue($id_token2->hasClaim('c_hash'));
        $this->assertTrue($id_token->getClaim('c_hash') === $id_token2->getClaim('c_hash'));
    }

    public function testCodeIdTokenSuccess()
    {
        $request = new ServerRequest();
        $request = $request->withQueryParams([
            'redirect_uri'          => 'http://example.com/test?good=false',
            'client_id'             => 'foo',
            'response_type'         => 'code id_token',
            'state'                 => 'ABCDEF',
            'scope'                 => 'openid',
            'nonce'                 => '0123456789',
            'code_challenge'        => 'E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM',
            'code_challenge_method' => 'plain',
        ]);
        $authorization = $this->getAuthorizationFactory()->createFromRequest(
            $request,
            $this->getUserManager()->getUser('user1'),
            true
        );

        $response = new Response();
        $this->getAuthorizationEndpoint()->authorize($authorization, $response);
        $this->assertRegExp('/^http:\/\/example.com\/test\?good=false#code=[^"]+&state=ABCDEF&id_token=[^"]+$/', $response->getHeader('Location')[0]);
        $values = parse_url($response->getHeader('Location')[0]);
        parse_str($values['fragment'], $params);

        $loader = new Loader();
        $id_token = $loader->load($params['id_token']);

        $this->assertInstanceOf(JWSInterface::class, $id_token);
        $this->assertTrue($id_token->hasClaim('nonce'));
        $this->assertEquals('0123456789', $id_token->getClaim('nonce'));
        $this->assertTrue($id_token->hasClaim('c_hash'));

        $response = new Response();
        $request = $this->createRequest('/', 'POST', ['client_id' => 'foo', 'grant_type' => 'authorization_code', 'code' => $params['code'], 'redirect_uri' => 'http://example.com/test?good=false', 'code_verifier' => 'E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM'], ['HTTPS' => 'on'], ['X-OAuth2-Public-Client-ID' => 'foo']);

        $this->getTokenEndpoint()->getAccessToken($request, $response);
        $response->getBody()->rewind();

        $this->assertEquals('application/json', $response->getHeader('Content-Type')[0]);
        $this->assertEquals('no-store, private', $response->getHeader('Cache-Control')[0]);
        $this->assertEquals(200, $response->getStatusCode());
        $this->assertEquals('no-cache', $response->getHeader('Pragma')[0]);
        $this->assertRegExp('{"access_token":"[^"]+","token_type":"Bearer","expires_in":[\d]+,"scope":"openid","foo":"bar","id_token":"[^"]+"}', $response->getBody()->getContents());

        $response->getBody()->rewind();
        $json = json_decode($response->getBody()->getContents(), true);

        $access_token = $this->getJWTAccessTokenManager()->getAccessToken($json['access_token']);

        $this->assertInstanceOf(AccessTokenInterface::class, $access_token);
        $this->assertTrue($this->getJWTAccessTokenManager()->isAccessTokenValid($access_token));

        $loader = new Loader();
        $id_token2 = $loader->load($json['id_token']);

        $this->assertInstanceOf(JWSInterface::class, $id_token2);
        $this->assertTrue($id_token2->hasClaim('nonce'));
        $this->assertEquals('0123456789', $id_token2->getClaim('nonce'));
        $this->assertTrue($id_token2->hasClaim('c_hash'));
        $this->assertTrue($id_token->getClaim('c_hash') === $id_token2->getClaim('c_hash'));
    }

    public function testNoneSuccess()
    {
        $request = new ServerRequest();
        $request = $request->withQueryParams([
            'redirect_uri'  => 'http://example.com/test?good=false',
            'client_id'     => 'foo',
            'response_type' => 'none',
            'state'         => '0123456789',
        ]);
        $authorization = $this->getAuthorizationFactory()->createFromRequest(
            $request,
            $this->getUserManager()->getUser('user1'),
            true
        );

        $response = new Response();
        $this->getAuthorizationEndpoint()->authorize($authorization, $response);

        $this->assertEquals('http://example.com/test?good=false&state=0123456789#', $response->getHeader('Location')[0]);
        $this->assertEquals(1, count($this->getNoneListener()->getAccessTokens()));

        $access_tokens = $this->getNoneListener()->getAccessTokens();
        $this->assertInstanceOf(AccessTokenInterface::class, $access_tokens[0]);
    }

    public function testMetadataAvailable()
    {
        $metadata = $this->getMetadata();

        $this->assertInstanceOf(Metadata::class, $metadata);
    }

    public function testUserInfoUsingUnsecuredRequest()
    {
        $request = $this->createRequest('/', 'GET', [], [], ['authorization' => 'Bearer USER_INFO']);

        try {
            $this->getListener()->handle($request);
            $this->fail('Should throw an Exception');
        } catch (BaseException $e) {
            $this->assertInstanceOf(BadRequestExceptionInterface::class, $e);
            $this->assertEquals('invalid_request', $e->getMessage());
            $this->assertEquals('The request must be secured.', $e->getDescription());
            $this->assertEquals(400, $e->getCode());
        }
    }

    public function testEntryPoint()
    {
        $request = $this->createRequest();
        $response = new Response();

        $this->getEntryPoint()->start($request, $response);
        $this->assertEquals(401, $response->getStatusCode());
        $this->assertEquals(['Bearer', 'MAC'], $response->getHeader('www-authenticate'));
        $this->assertEquals(['no-store'], $response->getHeader('cache-control'));
        $this->assertEquals(['no-cache'], $response->getHeader('pragma'));
    }

    public function testUserInfoRequestWithoutAccessToken()
    {
        $request = $this->createRequest('/', 'GET', [], ['HTTPS' => 'on'], ['authorization' => 'Bearer']);

        try {
            $this->getListener()->handle($request);
            $this->fail('Should throw an Exception');
        } catch (BaseException $e) {
            $this->assertInstanceOf(AuthenticateExceptionInterface::class, $e);
            $this->assertEquals('invalid_token', $e->getMessage());
            $this->assertEquals('Access token required.', $e->getDescription());
            $this->assertEquals(401, $e->getCode());
        }
    }

    public function testUserInfoRequestWithInvalidAccessToken()
    {
        $request = $this->createRequest('/', 'GET', [], ['HTTPS' => 'on'], ['authorization' => 'Bearer FOOBAR']);

        try {
            $access_token = $this->getListener()->handle($request);
            $this->getUserInfo()->getUserinfo(
                $this->getClientManager()->getClient($access_token->getClientPublicId()),
                $this->getUserManager()->getUser($access_token->getResourceOwnerPublicId()),
                $access_token->getRedirectUri(),
                $access_token->getScope()
            );
            $this->fail('Should throw an Exception');
        } catch (BaseException $e) {
            $this->assertInstanceOf(AuthenticateExceptionInterface::class, $e);
            $this->assertEquals('invalid_token', $e->getMessage());
            $this->assertEquals('Access token does not exist or is not valid.', $e->getDescription());
            $this->assertEquals(401, $e->getCode());
        }
    }

    public function testUserInfoRequestWithValidAccessTokenButNoOpenIDScope()
    {
        $request = $this->createRequest('/', 'GET', [], ['HTTPS' => 'on'], ['authorization' => 'Bearer NO_USER_INFO']);

        try {
            $access_token = $this->getListener()->handle($request);
            $this->getUserInfo()->getUserinfo(
                $this->getClientManager()->getClient($access_token->getClientPublicId()),
                $this->getUserManager()->getUser($access_token->getResourceOwnerPublicId()),
                $access_token->getRedirectUri(),
                $access_token->getScope()
            );
            $this->fail('Should throw an Exception');
        } catch (BaseException $e) {
            $this->assertInstanceOf(BadRequestExceptionInterface::class, $e);
            $this->assertEquals('invalid_request', $e->getMessage());
            $this->assertEquals('Access token does not contain the "openid" scope.', $e->getDescription());
            $this->assertEquals(400, $e->getCode());
        }
    }

    public function testUserInfoSuccess()
    {
        $request = $this->createRequest('/', 'GET', [], ['HTTPS' => 'on'], ['authorization' => 'Bearer USER_INFO']);

        $access_token = $this->getListener()->handle($request);
        $data = $this->getUserInfoEndpoint()->handle($access_token);

        $loader = new Loader();
        $id_token = $loader->load($data);

        $this->assertTrue($id_token->hasClaim('exp'));
        $this->assertTrue($id_token->hasClaim('nbf'));
        $this->assertTrue($id_token->hasClaim('iat'));
        $this->assertTrue($id_token->hasClaim('sub'));
        $this->assertTrue($id_token->hasClaim('aud'));
        $this->assertTrue($id_token->hasClaim('iss'));
        $this->assertTrue($id_token->hasClaim('birthdate'));
        $this->assertTrue($id_token->hasClaim('email'));
        $this->assertTrue($id_token->hasClaim('email_verified'));
        $this->assertTrue($id_token->hasClaim('address'));
    }

    public function testUserInfoSuccessAndEncrypted()
    {
        $request = $this->createRequest('/', 'GET', [], ['HTTPS' => 'on'], ['authorization' => 'Bearer USER_INFO2']);

        $access_token = $this->getListener()->handle($request);
        $data = $this->getUserInfoEndpoint()->handle($access_token);

        $loader = new Loader();
        $jwt = $loader->load($data);

        $this->assertInstanceOf(JWEInterface::class, $jwt);
        $decrypter = new Decrypter(['A256KW'], ['A256CBC-HS512'], []);
        $decrypter->decryptUsingKey($jwt, new JWK([
            'kid' => 'JWK1',
            'use' => 'enc',
            'kty' => 'oct',
            'k'   => 'ABEiM0RVZneImaq7zN3u_wABAgMEBQYHCAkKCwwNDg8',
        ]));
        $id_token = $loader->load($jwt->getPayload());
        $this->assertInstanceOf(JWSInterface::class, $id_token);

        $this->assertTrue($id_token->hasClaim('exp'));
        $this->assertTrue($id_token->hasClaim('nbf'));
        $this->assertTrue($id_token->hasClaim('iat'));
        $this->assertTrue($id_token->hasClaim('sub'));
        $this->assertTrue($id_token->hasClaim('aud'));
        $this->assertTrue($id_token->hasClaim('iss'));
        $this->assertTrue($id_token->hasClaim('birthdate'));
        $this->assertTrue($id_token->hasClaim('email'));
        $this->assertTrue($id_token->hasClaim('email_verified'));
        $this->assertTrue($id_token->hasClaim('address'));
    }
}
