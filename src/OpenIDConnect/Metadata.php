<?php

/*
 * The MIT License (MIT)
 *
 * Copyright (c) 2014-2016 Spomky-Labs
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file for details.
 */

namespace OAuth2\OpenIDConnect;

use Assert\Assertion;

/**
 * @method setIssuer($value)
 * @method getIssuer()
 * @method setAuthorizationEndpoint($value)
 * @method getAuthorizationEndpoint()
 * @method setTokenEndpoint($value)
 * @method getTokenEndpoint()
 * @method setUserinfoEndpoint($value)
 * @method getUserinfoEndpoint()
 * @method setJwksUri($value)
 * @method getJwksUri()
 * @method setRegistrationEndpoint($value)
 * @method getRegistrationEndpoint()
 * @method setScopesSupported($value)
 * @method getScopesSupported()
 * @method setResponseTypesSupported($value)
 * @method getResponseTypesSupported()
 * @method setResponseModesSupported($value)
 * @method getResponseModesSupported()
 * @method setGrantTypesSupported($value)
 * @method getGrantTypesSupported()
 * @method setAcrValuesSupported($value)
 * @method getAcrValuesSupported()
 * @method setSubjectTypesSupported($value)
 * @method getSubjectTypesSupported()
 * @method setIdTokenSigningAlgValuesSupported($value)
 * @method getIdTokenSigningAlgValuesSupported()
 * @method setIdTokenEncryptionAlgValuesSupported($value)
 * @method getIdTokenEncryptionAlgValuesSupported()
 * @method setIdTokenEncryptionEncValuesSupported($value)
 * @method getIdTokenEncryptionEncValuesSupported()
 * @method setUserinfoSigningAlgValuesSupported($value)
 * @method getUserinfoSigningAlgValuesSupported()
 * @method setUserinfoEncryptionAlgValuesSupported($value)
 * @method getUserinfoEncryptionAlgValuesSupported()
 * @method setUserinfoEncryptionEncValuesSupported($value)
 * @method getUserinfoEncryptionEncValuesSupported()
 * @method setRequestObjectSigningAlgValuesSupported($value)
 * @method getRequestObjectSigningAlgValuesSupported()
 * @method setRequestObjectEncryptionAlgValuesSupported($value)
 * @method getRequestObjectEncryptionAlgValuesSupported()
 * @method setRequestObjectEncryptionEncValuesSupported($value)
 * @method getRequestObjectEncryptionEncValuesSupported()
 * @method setTokenEndpointAuthMethodsSupported($value)
 * @method getTokenEndpointAuthMethodsSupported()
 * @method setTokenEndpointAuthSigningAlgValuesSupported($value)
 * @method getTokenEndpointAuthSigningAlgValuesSupported()
 * @method setTokenEndpointAuthEncryptionAlgValuesSupported($value)
 * @method getTokenEndpointAuthEncryptionAlgValuesSupported()
 * @method setTokenEndpointAuthEncryptionEncValuesSupported($value)
 * @method getTokenEndpointAuthEncryptionEncValuesSupported()
 * @method setDisplayValuesSupported($value)
 * @method getDisplayValuesSupported()
 * @method setClaimTypesSupported($value)
 * @method getClaimTypesSupported()
 * @method setClaimsSupported($value)
 * @method getClaimsSupported()
 * @method setServiceDocumentation($value)
 * @method getServiceDocumentation()
 * @method setClaimsLocalesSupported($value)
 * @method getClaimsLocalesSupported()
 * @method setUiLocalesSupported($value)
 * @method getUiLocalesSupported()
 * @method setClaimsParameterSupported($value)
 * @method getClaimsParameterSupported()
 * @method setRequestParameterSupported($value)
 * @method getRequestParameterSupported()
 * @method setRequestUriParameterSupported($value)
 * @method getRequestUriParameterSupported()
 * @method setRequireRequestUriRegistration($value)
 * @method getRequireRequestUriRegistration()
 * @method setOpPolicyUri($value)
 * @method getOpPolicyUri()
 * @method setOpTosUri($value)
 * @method getOpTosUri()
 */
final class Metadata implements \JsonSerializable
{
    /**
     * @var array
     */
    private $values = [];

    /**
     * @param string $name
     * @param $arguments
     *
     * @return mixed
     */
    public function __call($name, array $arguments)
    {
        if (method_exists($this, $name)) {
            return call_user_func([$this, $name], $arguments);
        }

        $method = mb_substr($name, 0, 3, '8bit');
        if (in_array($method, ['get', 'set'])) {
            $key = $this->decamelize(mb_substr($name, 3, null, '8bit'));
            $arguments = array_merge(
                [$key],
                $arguments
            );

            return call_user_func_array([$this, $method], $arguments);
        }
        throw new \BadMethodCallException(sprintf('Method "%s" does not exists.', $name));
    }

    /**
     * @param string $key
     *
     * @return bool
     */
    public function has($key)
    {
        Assertion::string($key);

        return array_key_exists($key, $this->values);
    }

    /**
     * @param string $key
     *
     * @return mixed
     */
    public function get($key)
    {
        Assertion::true($this->has($key), sprintf('Configuration value with key "%s" does not exist.', $key));

        return $this->values[$key];
    }

    /**
     * @param string $key
     * @param mixed  $value
     */
    public function set($key, $value)
    {
        Assertion::string($key);
        $this->values[$key] = $value;
    }

    /**
     * @param $key
     */
    public function remove($key)
    {
        if (true === $this->has($key)) {
            unset($this->values[$key]);
        }
    }

    /**
     * @param string $word
     *
     * @return string
     */
    private function decamelize($word)
    {
        return preg_replace_callback(
            '/(^|[a-z])([A-Z])/',
            function ($m) { return mb_strtolower(mb_strlen($m[1], '8bit') ? sprintf("%s_%s", $m[1], $m[2]) : $m[2], '8bit'); },
            $word
        );
    }

    /**
     * {@inheritdoc}
     */
    public function jsonSerialize()
    {
        return $this->values;
    }
}
