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
        if (!is_null($client->getPlaintextSecret())) {
            $secret = hash($this->getHashAlgorithm(), $client->getSalt().$client->getPlaintextSecret());
            $client->setSecret($secret);

            if ($client instanceof PasswordClientWithDigestSupportInterface) {
                $a1MD5 = md5(sprintf('%s:%s:%s', $client->getPublicId(), $this->getConfiguration()->get('realm', 'Service'), $client->getPlaintextSecret()));
                $client->setA1Hash($a1MD5);
            }
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
            $algorithm = $this->getConfiguration()->get('digest_authentication_scheme_algorithm', 'MD5');
            $request->getBody()->rewind();
            $content_hash = md5($request->getBody()->getContents());
            if (!$client instanceof PasswordClientWithDigestSupportInterface) {
                $secret = !empty($client->getPlaintextSecret())?$client->getPlaintextSecret():$client->getSecret();
                return $client_credentials->getResponse() === $client_credentials->calculateServerDigestUsingPassword($secret, $request->getMethod(), $algorithm, $content_hash);
            }
            return $client_credentials->getResponse() === $client_credentials->calculateServerDigestUsingA1MD5($client->getA1Hash(), $request->getMethod(), $algorithm, $content_hash);

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
