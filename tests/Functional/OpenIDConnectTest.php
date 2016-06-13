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
use OAuth2\Token\RefreshTokenInterface;
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
            'claims_locales'        => ['fr_fr', 'fr', 'de', 'en'],
            'claims'                => ['id_token' => ['email' => ['essential' => true], 'email_verified' => ['essential' => true]], 'userinfo' => ['website' => ['essential' => false], 'picture' => ['essential' => false]]],
        ]);
        $response = new Response();
        $this->getAuthorizationEndpoint()->setCurrentUser('user1');
        $this->getAuthorizationEndpoint()->setIsAuthorized(true);
        $this->getAuthorizationEndpoint()->authorize($request, $response);
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
            $this->getAuthorizationFactory()->getResponseTypesSupported()
        );
        $this->assertFalse($id_token->hasClaim('website'));
        $this->assertFalse($id_token->hasClaim('picture'));
        $this->assertTrue($id_token->hasClaim('email'));
        $this->assertTrue($id_token->hasClaim('email_verified'));
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
        
        $this->assertTrue($userinfo->hasClaim('website#fr_fr'));
        $this->assertTrue($userinfo->hasClaim('picture#de'));
        $this->assertFalse($userinfo->hasClaim('email'));
        $this->assertFalse($userinfo->hasClaim('email_verified'));
        $this->assertEquals($userinfo->getClaim('sub'), $id_token->getClaim('sub'));
        $this->assertEquals($userinfo->getClaim('exp'), $id_token->getClaim('exp'));
        $this->assertEquals($userinfo->getClaim('iss'), $id_token->getClaim('iss'));
        $this->assertEquals($userinfo->getClaim('aud'), $id_token->getClaim('aud'));
    }

    public function testClaimSource()
    {
        $client = $this->getClientManager()->getClient('Mufasa');
        $user = $this->getUserManager()->getUser('user2');
        $result = $this->getUserInfo()->getUserinfo($client, $user, 'https://foo.bar/', null, [], ['openid', 'email']);

        $this->assertEquals('OkKmIBUobGzXso3FyJo3yY0XzMPRS0AD-DjTXjIGLaq6VPuJtfyYQX2JiSXmtisuGuON05BhHQj2jQ17I09lRQ', $result['sub']);
        $this->assertArrayHasKey('_claim_names', $result);
        $this->assertArrayHasKey('email', $result['_claim_names']);
        $this->assertArrayHasKey('_claim_sources', $result);
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

    public function testCodeTokenSuccessWithRefreshToken()
    {
        $request = new ServerRequest();
        $request = $request->withQueryParams([
            'redirect_uri'          => 'http://example.com/test?good=false',
            'client_id'             => 'Mufasa',
            'response_type'         => 'code token',
            'code_challenge'        => 'E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM',
            'code_challenge_method' => 'plain',
            'state'                 => 'ABCDEF',
            'scope'                 => 'openid offline_access',
            'nonce'                 => '0123456789',
            'prompt'                => 'consent',
        ]);
        $response = new Response();
        $this->getAuthorizationEndpoint()->setCurrentUser('user1');
        $this->getAuthorizationEndpoint()->setIsAuthorized(true);
        $this->getAuthorizationEndpoint()->authorize($request, $response);
        $this->assertRegExp('/^http:\/\/example.com\/test\?good=false#code=[^"]+&access_token=[^"]+&token_type=Bearer&expires_in=[\d]+&scope=openid\+offline_access&foo=bar&state=ABCDEF$/', $response->getHeader('Location')[0]);
        $values = parse_url($response->getHeader('Location')[0]);
        parse_str($values['fragment'], $params);

        $response = new Response();
        $request = $this->createRequest('/', 'POST', ['grant_type' => 'authorization_code', 'code' => $params['code'], 'redirect_uri' => 'http://example.com/test?good=false', 'code_verifier' => 'E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM'], ['HTTPS' => 'on', 'PHP_AUTH_USER' => 'Mufasa', 'PHP_AUTH_PW' => 'Circle Of Life']);

        $this->getTokenEndpoint()->getAccessToken($request, $response);
        $response->getBody()->rewind();

        $this->assertEquals('application/json', $response->getHeader('Content-Type')[0]);
        $this->assertEquals('no-store, private', $response->getHeader('Cache-Control')[0]);
        $this->assertEquals(200, $response->getStatusCode());
        $this->assertEquals('no-cache', $response->getHeader('Pragma')[0]);
        $this->assertRegExp('/^{"access_token":"[^"]+","token_type":"Bearer","expires_in":[\d]+,"scope":"openid offline_access","refresh_token":"[^"]+","foo":"bar","id_token":"[^"]+"}$/', $response->getBody()->getContents());

        $response->getBody()->rewind();
        $json = json_decode($response->getBody()->getContents(), true);

        $access_token = $this->getJWTAccessTokenManager()->getAccessToken($json['access_token']);
        $refresh_token = $this->getRefreshTokenManager()->getRefreshToken($json['refresh_token']);

        $this->assertInstanceOf(AccessTokenInterface::class, $access_token);
        $this->assertInstanceOf(RefreshTokenInterface::class, $refresh_token);
        $this->assertTrue($this->getJWTAccessTokenManager()->isAccessTokenValid($access_token));

        $introspection_request = $this->createRequest('/', 'POST', ['token' => $json['access_token']], ['HTTPS' => 'on', 'PHP_AUTH_USER' => 'Mufasa', 'PHP_AUTH_PW' => 'Circle Of Life']);

        $introspection_response = new Response();
        $this->getTokenIntrospectionEndpoint()->introspection($introspection_request, $introspection_response);
        $introspection_response->getBody()->rewind();

        $this->assertEquals(200, $introspection_response->getStatusCode());
        $this->assertRegExp('/^{"active":true,"client_id":"Mufasa","token_type":"Bearer","exp":[\d]+,"scp":\["openid"\,"offline_access"\],"jti":"[^"]+","iat":[\d]+,"nbf":[\d]+,"aud":"[^"]+","iss":"[^"]+"}$/', $introspection_response->getBody()->getContents());
    }

    /**
     * Refresh token is not issued because the prompt=consent parameter is not set
     */
    public function testCodeTokenSuccessWithoutRefreshToken()
    {
        $request = new ServerRequest();
        $request = $request->withQueryParams([
            'redirect_uri'          => 'http://example.com/test?good=false',
            'client_id'             => 'Mufasa',
            'response_type'         => 'code token',
            'code_challenge'        => 'E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM',
            'code_challenge_method' => 'plain',
            'state'                 => 'ABCDEF',
            'scope'                 => 'openid offline_access',
            'nonce'                 => '0123456789',
        ]);
        $response = new Response();
        $this->getAuthorizationEndpoint()->setCurrentUser('user1');
        $this->getAuthorizationEndpoint()->setIsAuthorized(true);
        $this->getAuthorizationEndpoint()->authorize($request, $response);
        $this->assertRegExp('/^http:\/\/example.com\/test\?good=false#code=[^"]+&access_token=[^"]+&token_type=Bearer&expires_in=[\d]+&scope=openid&foo=bar&state=ABCDEF$/', $response->getHeader('Location')[0]);
        $values = parse_url($response->getHeader('Location')[0]);
        parse_str($values['fragment'], $params);

        $response = new Response();
        $request = $this->createRequest('/', 'POST', ['grant_type' => 'authorization_code', 'code' => $params['code'], 'redirect_uri' => 'http://example.com/test?good=false', 'code_verifier' => 'E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM'], ['HTTPS' => 'on', 'PHP_AUTH_USER' => 'Mufasa', 'PHP_AUTH_PW' => 'Circle Of Life']);

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

        $introspection_request = $this->createRequest('/', 'POST', ['token' => $json['access_token']], ['HTTPS' => 'on', 'PHP_AUTH_USER' => 'Mufasa', 'PHP_AUTH_PW' => 'Circle Of Life']);

        $introspection_response = new Response();
        $this->getTokenIntrospectionEndpoint()->introspection($introspection_request, $introspection_response);
        $introspection_response->getBody()->rewind();

        $this->assertEquals(200, $introspection_response->getStatusCode());
        $this->assertRegExp('/^{"active":true,"client_id":"Mufasa","token_type":"Bearer","exp":[\d]+,"scp":\["openid"\],"jti":"[^"]+","iat":[\d]+,"nbf":[\d]+,"aud":"[^"]+","iss":"[^"]+"}$/', $introspection_response->getBody()->getContents());
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
            'claims'                => ['id_token' => ['email' => ['essential' => true], 'email_verified' => ['essential' => true]], 'userinfo' => ['email' => ['essential' => true], 'email_verified' => ['essential' => true]]],
        ]);
        $response = new Response();
        $this->getAuthorizationEndpoint()->setCurrentUser('user1');
        $this->getAuthorizationEndpoint()->setIsAuthorized(true);
        $this->getAuthorizationEndpoint()->authorize($request, $response);
        $this->assertRegExp('/^http:\/\/example.com\/test\?good=false#state=ABCDEF&id_token=[^"]+$/', $response->getHeader('Location')[0]);
        $values = parse_url($response->getHeader('Location')[0]);
        parse_str($values['fragment'], $params);

        $loader = new Loader();
        $id_token = $loader->load($params['id_token']);

        $this->assertInstanceOf(JWSInterface::class, $id_token);
        $this->assertTrue($id_token->hasClaim('email'));
        $this->assertTrue($id_token->hasClaim('email_verified'));
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
            'claims'                => ['id_token' => ['email' => ['essential' => true], 'email_verified' => ['essential' => true]], 'userinfo' => ['email' => ['essential' => true], 'email_verified' => ['essential' => true]]],
        ]);
        $response = new Response();
        $this->getAuthorizationEndpoint()->setCurrentUser('user1');
        $this->getAuthorizationEndpoint()->setIsAuthorized(true);
        $this->getAuthorizationEndpoint()->authorize($request, $response);
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

        $this->assertTrue($id_token->hasClaim('email'));
        $this->assertTrue($id_token->hasClaim('email_verified'));
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
            'claims'                => ['id_token' => ['email' => ['essential' => true], 'email_verified' => ['essential' => true]], 'userinfo' => ['email' => ['essential' => true], 'email_verified' => ['essential' => true]]],
        ]);
        $response = new Response();
        $this->getAuthorizationEndpoint()->setCurrentUser('user1');
        $this->getAuthorizationEndpoint()->setIsAuthorized(true);
        $this->getAuthorizationEndpoint()->authorize($request, $response);
        $this->assertRegExp('/^http:\/\/example.com\/test\?good=false#access_token=[^"]+&token_type=Bearer&expires_in=[\d]+&scope=openid&foo=bar&state=ABCDEF&id_token=[^"]+$/', $response->getHeader('Location')[0]);
        $values = parse_url($response->getHeader('Location')[0]);
        parse_str($values['fragment'], $params);

        $loader = new Loader();
        $id_token = $loader->load($params['id_token']);

        $this->assertInstanceOf(JWSInterface::class, $id_token);
        $this->assertTrue($id_token->hasClaim('email'));
        $this->assertTrue($id_token->hasClaim('email_verified'));
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
            'claims'                => ['id_token' => ['email' => ['essential' => true], 'email_verified' => ['essential' => true]], 'userinfo' => ['email' => ['essential' => true], 'email_verified' => ['essential' => true]]],
        ]);
        $response = new Response();
        $this->getAuthorizationEndpoint()->setCurrentUser('user1');
        $this->getAuthorizationEndpoint()->setIsAuthorized(true);
        $this->getAuthorizationEndpoint()->authorize($request, $response);
        $this->assertRegExp('/^http:\/\/example.com\/test\?good=false#code=[^"]+&access_token=[^"]+&token_type=Bearer&expires_in=[\d]+&scope=openid&foo=bar&state=ABCDEF&id_token=[^"]+$/', $response->getHeader('Location')[0]);
        $values = parse_url($response->getHeader('Location')[0]);
        parse_str($values['fragment'], $params);

        $loader = new Loader();
        $id_token = $loader->load($params['id_token']);

        $this->assertInstanceOf(JWSInterface::class, $id_token);
        $this->assertTrue($id_token->hasClaim('email'));
        $this->assertTrue($id_token->hasClaim('email_verified'));
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
        $this->assertTrue($id_token2->hasClaim('email'));
        $this->assertTrue($id_token2->hasClaim('email_verified'));
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
            'claims'                => ['id_token' => ['email' => ['essential' => true], 'email_verified' => ['essential' => true]], 'userinfo' => ['email' => ['essential' => true], 'email_verified' => ['essential' => true]]],
        ]);
        $response = new Response();
        $this->getAuthorizationEndpoint()->setCurrentUser('user1');
        $this->getAuthorizationEndpoint()->setIsAuthorized(true);
        $this->getAuthorizationEndpoint()->authorize($request, $response);
        $this->assertRegExp('/^http:\/\/example.com\/test\?good=false#code=[^"]+&state=ABCDEF&id_token=[^"]+$/', $response->getHeader('Location')[0]);
        $values = parse_url($response->getHeader('Location')[0]);
        parse_str($values['fragment'], $params);

        $loader = new Loader();
        $id_token = $loader->load($params['id_token']);

        $this->assertInstanceOf(JWSInterface::class, $id_token);
        $this->assertTrue($id_token->hasClaim('email'));
        $this->assertTrue($id_token->hasClaim('email_verified'));
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
        $this->assertTrue($id_token2->hasClaim('email'));
        $this->assertTrue($id_token2->hasClaim('email_verified'));
        $this->assertTrue($id_token2->hasClaim('nonce'));
        $this->assertEquals('0123456789', $id_token2->getClaim('nonce'));
        $this->assertTrue($id_token2->hasClaim('c_hash'));
        $this->assertTrue($id_token->getClaim('c_hash') === $id_token2->getClaim('c_hash'));
    }

    public function testNoneGrantTypeSuccess()
    {
        $request = new ServerRequest();
        $request = $request->withQueryParams([
            'redirect_uri'  => 'http://example.com/test?good=false',
            'client_id'     => 'foo',
            'response_type' => 'none',
            'state'         => '0123456789',
        ]);
        $response = new Response();
        $this->getAuthorizationEndpoint()->setCurrentUser('user1');
        $this->getAuthorizationEndpoint()->setIsAuthorized(true);
        $this->getAuthorizationEndpoint()->authorize($request, $response);

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
                $access_token->getMetadata('redirect_uri'),
                null,
                [],
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
                $access_token->getMetadata('redirect_uri'),
                null,
                [],
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

        $this->assertTrue($id_token->hasClaim('email'));
        $this->assertTrue($id_token->hasClaim('email_verified'));
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

        $this->assertTrue($id_token->hasClaim('email'));
        $this->assertTrue($id_token->hasClaim('email_verified'));
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

    public function testPromptLoginWithNotFullyAuthenticatedUser()
    {
        $request = new ServerRequest();
        $request = $request->withQueryParams([
            'redirect_uri'  => 'http://example.com/test?good=false',
            'client_id'     => 'foo',
            'response_type' => 'none',
            'prompt'        => 'login',
            'state'         => '0123456789',
        ]);
        $response = new Response();
        $this->getAuthorizationEndpoint()->setCurrentUser('user1');
        $this->getAuthorizationEndpoint()->setUserFullyAuthenticated(false);
        $this->getAuthorizationEndpoint()->authorize($request, $response);

        $response->getBody()->rewind();
        $this->assertEquals('You are redirected to the login page', $response->getBody()->getContents());
    }

    public function testPromptLoginWithFullyAuthenticatedUser()
    {
        $request = new ServerRequest();
        $request = $request->withQueryParams([
            'redirect_uri'  => 'http://example.com/test?good=false',
            'client_id'     => 'foo',
            'response_type' => 'none',
            'prompt'        => 'login',
            'state'         => '0123456789',
        ]);
        $response = new Response();
        $this->getAuthorizationEndpoint()->setCurrentUser('user1');
        $this->getAuthorizationEndpoint()->setIsAuthorized(true);
        $this->getAuthorizationEndpoint()->setUserFullyAuthenticated(true);
        $this->getAuthorizationEndpoint()->authorize($request, $response);

        $this->assertEquals('http://example.com/test?good=false&state=0123456789#', $response->getHeader('Location')[0]);
        $this->assertEquals(1, count($this->getNoneListener()->getAccessTokens()));

        $access_tokens = $this->getNoneListener()->getAccessTokens();
        $this->assertInstanceOf(AccessTokenInterface::class, $access_tokens[0]);
    }

    public function testPromptLoginWithFullyAuthenticatedUserButConsentNotGiven()
    {
        $request = new ServerRequest();
        $request = $request->withQueryParams([
            'redirect_uri'  => 'http://example.com/test?good=false',
            'client_id'     => 'foo',
            'response_type' => 'none',
            'prompt'        => 'login',
            'state'         => '0123456789',
        ]);
        $response = new Response();
        $this->getAuthorizationEndpoint()->setCurrentUser('user1');
        $this->getAuthorizationEndpoint()->setIsAuthorized(null);
        $this->getAuthorizationEndpoint()->setUserFullyAuthenticated(true);
        $this->getAuthorizationEndpoint()->authorize($request, $response);

        $response->getBody()->rewind();
        $this->assertEquals('You are on the consent screen', $response->getBody()->getContents());
    }

    public function testPromptLoginWithFullyAuthenticatedUserAndConsentGiven()
    {
        $request = new ServerRequest();
        $request = $request->withQueryParams([
            'redirect_uri'  => 'http://example.com/test?good=false',
            'client_id'     => 'foo',
            'response_type' => 'token',
            'prompt'        => 'login',
            'scope'         => 'openid email profile',
            'state'         => '0123456789',
        ]);
        $response = new Response();
        $this->getAuthorizationEndpoint()->setCurrentUser('user1');
        $this->getAuthorizationEndpoint()->setIsAuthorized(null);
        $this->getAuthorizationEndpoint()->setUserFullyAuthenticated(true);
        $this->getAuthorizationEndpoint()->authorize($request, $response);

        $this->assertRegExp('/^http:\/\/example.com\/test\?good=false#access_token=[^"]+&token_type=Bearer&expires_in=[\d]+&scope=openid\+email\+profile&foo=bar&state=0123456789$/', $response->getHeader('Location')[0]);
    }

    public function testPromptNoneWithNotFullyAuthenticatedUser()
    {
        $request = new ServerRequest();
        $request = $request->withQueryParams([
            'redirect_uri'  => 'http://example.com/test?good=false',
            'client_id'     => 'foo',
            'response_type' => 'none',
            'prompt'        => 'none',
            'state'         => '0123456789',
        ]);
        $response = new Response();
        $this->getAuthorizationEndpoint()->authorize($request, $response);

        $this->assertEquals('http://example.com/test?good=false&error=login_required&error_uri=https%3A%2F%2Ffoo.test%2FError%2FRedirect%2Flogin_required&state=0123456789#', $response->getHeader('Location')[0]);
    }

    public function testPromptNoneWithAuthenticatedUserButConsentRequired()
    {
        $request = new ServerRequest();
        $request = $request->withQueryParams([
            'redirect_uri'  => 'http://example.com/test?good=false',
            'client_id'     => 'foo',
            'response_type' => 'none',
            'prompt'        => 'none',
            'state'         => '0123456789',
        ]);
        $response = new Response();
        $this->getAuthorizationEndpoint()->setCurrentUser('user1');
        $this->getAuthorizationEndpoint()->authorize($request, $response);

        $this->assertEquals('http://example.com/test?good=false&error=interaction_required&error_uri=https%3A%2F%2Ffoo.test%2FError%2FRedirect%2Finteraction_required&state=0123456789#', $response->getHeader('Location')[0]);
    }

    public function testPromptNoneWithAuthenticatedUserAndConsentGiven()
    {
        $request = new ServerRequest();
        $request = $request->withQueryParams([
            'redirect_uri'  => 'http://example.com/test?good=false',
            'client_id'     => 'foo',
            'response_type' => 'none',
            'prompt'        => 'none',
            'scope'         => 'openid email profile',
            'state'         => '0123456789',
        ]);
        $response = new Response();
        $this->getAuthorizationEndpoint()->setCurrentUser('user1');
        $this->getAuthorizationEndpoint()->setIsAuthorized(true);
        $this->getAuthorizationEndpoint()->authorize($request, $response);

        $this->assertEquals('http://example.com/test?good=false&state=0123456789#', $response->getHeader('Location')[0]);
        $this->assertEquals(1, count($this->getNoneListener()->getAccessTokens()));

        $access_tokens = $this->getNoneListener()->getAccessTokens();
        $this->assertInstanceOf(AccessTokenInterface::class, $access_tokens[0]);
    }

    public function testPromptNoneAndLogin()
    {
        $request = new ServerRequest();
        $request = $request->withQueryParams([
            'redirect_uri'  => 'http://example.com/test?good=false',
            'client_id'     => 'foo',
            'response_type' => 'none',
            'prompt'        => 'none login',
            'scope'         => 'openid email profile',
            'state'         => '0123456789',
        ]);
        $response = new Response();
        $this->getAuthorizationEndpoint()->setCurrentUser('user1');
        $this->getAuthorizationEndpoint()->authorize($request, $response);

        $response->getBody()->rewind();
        $this->assertEquals('{"error":"invalid_request","error_description":"Invalid parameter \"prompt\". Prompt value \"none\" must be used alone.","error_uri":"https:\/\/foo.test\/Error\/BadRequest\/invalid_request"}', $response->getBody()->getContents());
    }
}
