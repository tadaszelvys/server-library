<?php

namespace OAuth2\Client;

use OAuth2\Behaviour\HasConfiguration;
use OAuth2\Behaviour\HasExceptionManager;
use OAuth2\Exception\ExceptionManagerInterface;
use OAuth2\Util\RequestBody;
use Psr\Http\Message\ServerRequestInterface;

abstract class PasswordClientManager implements PasswordClientManagerInterface
{
    use HasExceptionManager;
    use HasConfiguration;

    /**
     * @return string
     */
    protected function getHashAlgorithm()
    {
        return 'sha512';
    }

    /**
     * {@inheritdoc}
     */
    public function getClientFromA1($a1)
    {
    }

    /**
     * @param \OAuth2\Client\PasswordClientInterface $client
     *
     * @return self
     */
    protected function updateClientCredentials(PasswordClientInterface $client)
    {
        if (!is_null($client->getPlaintextSecret())) {
            $secret = hash($this->getHashAlgorithm(), $client->getSalt().$client->getPlaintextSecret());
            $client->setSecret($secret);
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
        } elseif (is_array($client_credentials)) {
            if (!$client instanceof PasswordClientWithDigestSupportInterface) {
                return false;
            }
            $ha1 = $client->getA1Hash();
            if ('MD5-sess' === $this->getConfiguration()->get('digest_authentication_scheme_algorithm', null)) {
                $ha1 = hash('md5', $ha1.sprintf(':s%:s', $ha1, $client_credentials['nonce'], $client_credentials['cnonce']));
            }
            $a2 = sprintf('%s:%s', $request->getMethod(), $request->getRequestTarget());
            if (array_key_exists('qop', $client_credentials) && 'auth-int' === $client_credentials['qop']) {
                $request->getBody()->rewind();

                $a2 .= ':'.hash('md5', $request->getBody()->getContents());
            }
            $ha2 = hash('md5', $a2);
            $calculated_response = hash('md5', sprintf(
                '%s:%s:%s:%s:%s:%s',
                $ha1,
                $client_credentials['nonce'],
                $client_credentials['nc'],
                $client_credentials['cnonce'],
                $client_credentials['qop'],
                $ha2
            ));
            return $client_credentials['response'] === $calculated_response;
        }
        throw $this->getExceptionManager()->getException(ExceptionManagerInterface::INTERNAL_SERVER_ERROR, ExceptionManagerInterface::NOT_IMPLEMENTED, 'Client credentials type not supported');
    }

    /**
     * @return string[]
     */
    protected function findClientCredentialsMethods()
    {
        $methods = [
            'findCredentialsFromBasicAuthenticationScheme',
        ];

        // This authentication method is not enabled by default, but highly recommended as it provides a secured way to authenticate the client against the server.
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
    public function findClient(ServerRequestInterface $request, &$client_public_id_found = null)
    {
        $methods = $this->findClientCredentialsMethods();
        $credentials = [];

        foreach ($methods as $method) {
            $data = $this->$method($request, $client_public_id_found);
            if (!is_null($data)) {
                $credentials[] = $data;
            }
        }

        $client = $this->checkResult($credentials);
        if (is_null($client)) {
            return $client;
        }

        if (!$client instanceof PasswordClientInterface) {
            throw $this->getExceptionManager()->getException('InternalServerError', 'invalid_client', 'The client is not an instance of PasswordClientInterface.');
        }

        if (!$this->checkClientCredentials($client, $credentials[0]['client_credentials'], $request)) {
            $client_public_id_found = $client->getPublicId();

            return;
        }

        return $client;
    }

    /**
     * @param \Psr\Http\Message\ServerRequestInterface $request
     *
     * @return string[]
     */
    protected function findCredentialsFromDigestAuthenticationScheme(ServerRequestInterface $request, &$client_public_id_found = null)
    {
        $server_params = $request->getServerParams();
        if (array_key_exists('PHP_AUTH_DIGEST', $server_params)) {
            $parsed_digest = $this->parseDigest($server_params['PHP_AUTH_DIGEST'], $request);
            return [
                'client_id'          => $parsed_digest['username'],
                'client_credentials' => $parsed_digest,
            ];
        }
        $header = $request->getHeader('Authorization');
        if (0 < count($header) && strtolower(substr($header[0], 0, 7)) === 'digest ') {
            $parsed_digest = $this->parseDigest(substr($header[0], 7, strlen($header[0]) - 7), $request);
            return [
                'client_id'          => $parsed_digest['username'],
                'client_credentials' => $parsed_digest,
            ];
        }
    }

    /**
     * @param \Psr\Http\Message\ServerRequestInterface $request
     *
     * @return string[]
     */
    protected function findCredentialsFromBasicAuthenticationScheme(ServerRequestInterface $request, &$client_public_id_found = null)
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
    protected function findCredentialsFromRequestBody(ServerRequestInterface $request, &$client_public_id_found = null)
    {
        $client_id = RequestBody::getParameter($request, 'client_id');
        $client_secret = RequestBody::getParameter($request, 'client_secret');

        if (!is_null($client_id) && !is_null($client_secret)) {
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
     * @return null|\OAuth2\Client\ClientInterface
     */
    private function checkResult(array $result)
    {
        if (count($result) > 1) {
            throw $this->getExceptionManager()->getException(ExceptionManagerInterface::BAD_REQUEST, ExceptionManagerInterface::INVALID_REQUEST, 'Only one authentication method may be used to authenticate the client.');
        }

        if (count($result) < 1) {
            return;
        }

        return $this->getClient($result[0]['client_id']);
    }

    /**
     * @param string $digest
     * @param \Psr\Http\Message\ServerRequestInterface $request
     *
     * @throws \OAuth2\Exception\BaseExceptionInterface
     *
     * @return array
     */
    private function parseDigest($digest, ServerRequestInterface $request)
    {
        $needed_parts = [
            'nonce'=>1,
            'nc'=>1,
            'cnonce'=>1,
            'qop'=>1,
            'username'=>1,
            'uri'=>1,
            'response'=>1
        ];
        $data = [];

        preg_match_all('@(\w+)=(?:(?:")([^"]+)"|([^\s,$]+))@', $digest, $matches, PREG_SET_ORDER);

        foreach ($matches as $m) {
            $data[$m[1]] = $m[2] ? $m[2] : $m[3];
            unset($needed_parts[$m[1]]);
        }

        if (!empty($needed_parts)) {
            throw $this->getExceptionManager()->getException(ExceptionManagerInterface::BAD_REQUEST, ExceptionManagerInterface::INVALID_REQUEST, 'Bad HTTP Digest Authenticate message.');
        }

        if ($data['realm'] !== $this->getConfiguration()->get('realm', 'Service')) {
            throw $this->getExceptionManager()->getException(ExceptionManagerInterface::BAD_REQUEST, ExceptionManagerInterface::INVALID_REQUEST, 'Bad realm.');
        }

        if ($data['uri'] !== $request->getRequestTarget()) {
            throw $this->getExceptionManager()->getException(ExceptionManagerInterface::BAD_REQUEST, ExceptionManagerInterface::INVALID_REQUEST, 'Bad URI.');
        }

        return $data;
    }
}
