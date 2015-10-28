<?php

namespace OAuth2\Client;

use OAuth2\Behaviour\HasConfiguration;
use OAuth2\Behaviour\HasExceptionManager;
use OAuth2\Exception\ExceptionManagerInterface;
use OAuth2\Util\DigestData;
use OAuth2\Util\RequestBody;
use Psr\Http\Message\ServerRequestInterface;

abstract class PasswordClientManager implements ClientManagerInterface
{
    use HasExceptionManager;
    use HasConfiguration;

    /**
     * {@inheritdoc}
     */
    public function getSchemesParameters()
    {
        $key = $this->getConfiguration()->get('digest_authentication_key');
        if (empty($key)) {
            throw $this->getExceptionManager()->getException(ExceptionManagerInterface::INTERNAL_SERVER_ERROR, ExceptionManagerInterface::SERVER_ERROR, 'Parameter "digest_authentication_key" must be set');
        }
        $nonce_lifetime = $this->getConfiguration()->get('digest_authentication_nonce_lifetime', 300);

        $expiryTime = microtime(true) + $nonce_lifetime * 1000;
        $signatureValue = hash_hmac('sha512', $expiryTime.$key, $key, true);
        $nonceValue = $expiryTime.':'.$signatureValue;
        $nonceValueBase64 = base64_encode($nonceValue);

        $digest_params = [
            'realm'  => $this->getConfiguration()->get('realm', 'Service'),
            'nonce'  => $nonceValueBase64,
            'opaque' => base64_decode(hash_hmac('sha512', $nonceValueBase64.$this->getConfiguration()->get('realm', 'Service'), $key, true)),
        ];

        $qop = $this->getConfiguration()->get('digest_authentication_scheme_quality_of_protection', 'auth,auth-int');
        if (null !== $qop) {
            $digest_params['qop'] = $qop;
        }
        $algorithm = $this->configuration->get('digest_authentication_scheme_algorithm', null);
        if (null !== $algorithm) {
            $digest_params['algorithm'] = $algorithm;
        }

        return [
            'Basic' => [
                'realm' => $this->getConfiguration()->get('realm', 'Service'),
            ],
            'Digest' => $digest_params,
        ];
    }

    /**
     * @return string
     */
    protected function getHashAlgorithm()
    {
        return 'sha512';
    }

    /**
     * @param \OAuth2\Client\PasswordClientInterface $client
     *
     * @return self
     */
    protected function updateClientCredentials(PasswordClientInterface $client)
    {
        if (null !== ($client->getPlaintextSecret())) {
            $secret = hash($this->getHashAlgorithm(), $client->getSalt().$client->getPlaintextSecret());
            $client->setSecret($secret);

            $a1MD5 = md5(sprintf('%s:%s:%s', $client->getPublicId(), $this->getConfiguration()->get('realm', 'Service'), $client->getPlaintextSecret()));
            $client->setA1Hash($a1MD5);

            $client->clearCredentials();
        }

        return $this;
    }

    /**
     * @param \OAuth2\Client\PasswordClientInterface   $client
     * @param string|array                             $client_credentials
     * @param \Psr\Http\Message\ServerRequestInterface $request
     *
     * @throws \OAuth2\Exception\BaseExceptionInterface
     *
     * @return bool
     */
    protected function checkClientCredentials(PasswordClientInterface $client, $client_credentials, ServerRequestInterface $request)
    {
        if (is_string($client_credentials)) {
            return hash($this->getHashAlgorithm(), $client->getSalt().$client_credentials) === $client->getSecret();
        } elseif ($client_credentials instanceof DigestData) {
            if ($client_credentials->isNonceExpired()) {
                return false;
            }
            $algorithm = $this->getConfiguration()->get('digest_authentication_scheme_algorithm', 'MD5');
            $request->getBody()->rewind();
            $content_hash = md5($request->getBody()->getContents());

            $secret = !empty($client->getPlaintextSecret()) ? $client->getPlaintextSecret() : $client->getSecret();

            $result = $client_credentials->getResponse() === $client_credentials->calculateServerDigestUsingPassword($secret, $request->getMethod(), $algorithm, $content_hash);
            if (true === $result) {
                return true;
            }

            return $client_credentials->getResponse() === $client_credentials->calculateServerDigestUsingA1MD5($client->getA1Hash(), $request->getMethod(), $algorithm, $content_hash);
        }
        throw $this->getExceptionManager()->getException(ExceptionManagerInterface::INTERNAL_SERVER_ERROR, ExceptionManagerInterface::SERVER_ERROR, 'Client credentials type not supported');
    }

    /**
     * @return string[]
     */
    protected function findClientCredentialsMethods()
    {
        $methods = [
            'findCredentialsFromBasicAuthenticationScheme',
        ];

        // This authentication method is not enabled by default, but recommended as it provides a secured way to authenticate the client against the server.
        if ($this->getConfiguration()->get('enable_digest_authentication_scheme', true)) {
            $methods[] = 'findCredentialsFromDigestAuthenticationScheme';
        }

        // This authentication method is not recommended by the RFC6749. This option allows to disable this authentication method.
        // See http://tools.ietf.org/html/rfc6749#section-2.3.1
        if ($this->getConfiguration()->get('allow_password_client_credentials_in_body_request', true)) {
            $methods[] = 'findCredentialsFromRequestBody';
        }

        return $methods;
    }

    /**
     * {@inheritdoc}
     */
    public function findClient(ServerRequestInterface $request)
    {
        $methods = $this->findClientCredentialsMethods();
        $credentials = [];

        foreach ($methods as $method) {
            $data = $this->$method($request);
            if (null !== ($data)) {
                $credentials[] = $data;
            }
        }

        $client = $this->checkResult($credentials);
        if (null === $client) {
            return $client;
        }

        if (!$this->checkClientCredentials($client, $credentials[0]['client_credentials'], $request)) {
            throw $this->getExceptionManager()->getException(ExceptionManagerInterface::AUTHENTICATE, ExceptionManagerInterface::INVALID_CLIENT, 'Invalid client credentials.', ['schemes' => $this->getSchemesParameters()]);
        }

        return $client;
    }

    /**
     * @param \Psr\Http\Message\ServerRequestInterface $request
     *
     * @return string[]
     */
    protected function findCredentialsFromDigestAuthenticationScheme(ServerRequestInterface $request)
    {
        $server_params = $request->getServerParams();
        if (array_key_exists('PHP_AUTH_DIGEST', $server_params)) {
            $parsed_digest = $this->parseDigest($server_params['PHP_AUTH_DIGEST']);

            return [
                'client_id'          => $parsed_digest->getUsername(),
                'client_credentials' => $parsed_digest,
            ];
        }
        $header = $request->getHeader('Authorization');
        if (0 < count($header) && strtolower(substr($header[0], 0, 7)) === 'digest ') {
            $parsed_digest = $this->parseDigest(substr($header[0], 7, strlen($header[0]) - 7));

            return [
                'client_id'          => $parsed_digest->getUsername(),
                'client_credentials' => $parsed_digest,
            ];
        }
    }

    /**
     * @param \Psr\Http\Message\ServerRequestInterface $request
     *
     * @return string[]
     */
    protected function findCredentialsFromBasicAuthenticationScheme(ServerRequestInterface $request)
    {
        $server_params = $request->getServerParams();
        if (array_key_exists('PHP_AUTH_USER', $server_params) && array_key_exists('PHP_AUTH_PW', $server_params)) {
            return [
                'client_id'          => $server_params['PHP_AUTH_USER'],
                'client_credentials' => $server_params['PHP_AUTH_PW'],
            ];
        }
        $header = $request->getHeader('Authorization');
        if (0 < count($header) && strtolower(substr($header[0], 0, 6)) === 'basic ') {
            list($client_id, $client_secret) = explode(':', base64_decode(substr($header[0], 6, strlen($header[0]) - 6)));
            if (!empty($client_id) && !empty($client_secret)) {
                return [
                    'client_id'          => $client_id,
                    'client_credentials' => $client_secret,
                ];
            }
        }
    }

    /**
     * @param \Psr\Http\Message\ServerRequestInterface $request
     *
     * @return string[]|null
     */
    protected function findCredentialsFromRequestBody(ServerRequestInterface $request)
    {
        $client_id = RequestBody::getParameter($request, 'client_id');
        $client_secret = RequestBody::getParameter($request, 'client_secret');

        if (null !== ($client_id) && null !== ($client_secret)) {
            return [
                'client_id'          => $client_id,
                'client_credentials' => $client_secret,
            ];
        }
    }

    /**
     * @param array $result
     *
     * @throws \OAuth2\Exception\BaseExceptionInterface
     *
     * @return null|\OAuth2\Client\PasswordClientInterface
     */
    private function checkResult(array $result)
    {
        if (count($result) > 1) {
            throw $this->getExceptionManager()->getException(ExceptionManagerInterface::BAD_REQUEST, ExceptionManagerInterface::INVALID_REQUEST, 'Only one authentication method may be used to authenticate the client.');
        }

        if (count($result) < 1) {
            return;
        }

        $client = $this->getClient($result[0]['client_id']);

        if (!$client instanceof PasswordClientInterface) {
            throw $this->getExceptionManager()->getException(ExceptionManagerInterface::AUTHENTICATE, ExceptionManagerInterface::INVALID_CLIENT, 'Client authentication failed.', ['schemes' => $this->getSchemesParameters()]);
        }

        return $client;
    }

    /**
     * @param string $digest
     *
     * @throws \OAuth2\Exception\BaseExceptionInterface
     *
     * @return \OAuth2\Util\DigestData
     */
    private function parseDigest($digest)
    {
        $data = new DigestData($digest);
        $data->validateAndDecode(
            $this->getConfiguration()->get('digest_authentication_key'),
            $this->getConfiguration()->get('realm', 'Service')
        );

        return $data;
    }
}
