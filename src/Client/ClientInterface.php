<?php

/*
 * The MIT License (MIT)
 *
 * Copyright (c) 2014-2016 Spomky-Labs
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file for details.
 */

namespace OAuth2\Client;

use OAuth2\ResourceOwner\ResourceOwnerInterface;

/**
 * Interface ClientInterface.
 *
 * This interface is used for every client types.
 * A client is a resource owner with a set of allowed grant types and can perform requests against
 * available endpoints.
 * 
 * @method string[] getRedirectUris()
 * @method bool hasRedirectUris()
 * @method setRedirectUris(string[] $redirect_uris)
 * @method string getTokenEndpointAuthMethod()
 * @method bool hasTokenEndpointAuthMethod()
 * @method setTokenEndpointAuthMethod(string $token_endpoint_auth_method)
 * @method string[] getGrantTypes()
 * @method bool hasGrantTypes()
 * @method setGrantTypes(string[] $grant_types)
 * @method string[] getResponseTypes()
 * @method bool hasResponseTypes()
 * @method setResponseTypes(string[] $response_types)
 * @method string getClientName()
 * @method bool hasClientName()
 * @method setClientName(string $client_name)
 * @method string getClientUri()
 * @method bool hasClientUri()
 * @method setClientUri(string $client_uri)
 * @method string getLogoUri()
 * @method bool hasLogoUri()
 * @method setLogoUri(string $logo_uri)
 * @method string getScope()
 * @method bool hasScope()
 * @method setScope(string $scope)
 * @method string[] getContacts()
 * @method bool hasContacts()
 * @method setContacts(string[] $contacts)
 * @method string getTosUri()
 * @method bool hasTosUri()
 * @method setTosUri(string $tos_uri)
 * @method string getPolicyUri()
 * @method bool hasPolicyUri()
 * @method setPolicyUri(string $policy_uri)
 * @method string getJwksUri()
 * @method bool hasJwksUri()
 * @method setJwksUri(string $jwks_uri)
 * @method string getJwks()
 * @method bool hasJwks()
 * @method setJwks(string $jwks)
 * @method string getSoftwareId()
 * @method bool hasSoftwareId()
 * @method setSoftwareId(string $software_id)
 * @method string getSoftwareVersion()
 * @method bool hasSoftwareVersion()
 * @method setSoftwareVersion(string $software_version)
 * @method string getClientSecret()
 * @method bool hasClientSecret()
 * @method setClientSecret(string $client_secret)
 */
interface ClientInterface extends ResourceOwnerInterface
{
    /**
     * @param string $metadata
     *
     * @return bool
     */
    public function has($metadata);
    
    /**
     * @param string $metadata
     *
     * @return mixed
     */
    public function get($metadata);

    /**
     * @param string $metadata
     * @param mixed $value
     */
    public function set($metadata, $value);

    /**
     * @param string $metadata
     */
    public function remove($metadata);
    
    /**
     * Checks if the grant type is allowed for the client.
     *
     * @param string $grant_type The grant type
     *
     * @return bool true if the grant type is allowed, else false
     */
    public function isGrantTypeAllowed($grant_type);

    /**
     * Checks if the response type is allowed for the client.
     *
     * @param string $response_type The response type
     *
     * @return bool true if the response type is allowed, else false
     */
    public function isResponseTypeAllowed($response_type);
    
    /**
     * Checks if the token type is allowed for the client.
     *
     * @param string $token_type The token type
     *
     * @return bool true if the token type is allowed, else false
     */
    public function isTokenTypeAllowed($token_type);

    /**
     * @return bool
     */
    public function isPublic();

    /**
     * @return bool
     */
    public function areClientCredentialsExpired();

    /**
     * @return bool
     */
    public function hasPublicKeySet();

    /**
     * @return \Jose\Object\JWKSetInterface
     */
    public function getPublicKeySet();
}
