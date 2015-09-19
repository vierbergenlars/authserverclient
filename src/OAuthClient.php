<?php

namespace vierbergenlars\AuthserverClient;

use fkooman\Guzzle\Plugin\BearerAuth\BearerAuth;
use fkooman\Guzzle\Plugin\BearerAuth\Exception\BearerErrorResponseException;
use fkooman\OAuth\Client\Api;
use fkooman\OAuth\Client\Callback;
use fkooman\OAuth\Client\ClientConfig;
use fkooman\OAuth\Client\ClientConfigInterface;
use fkooman\OAuth\Client\Context;
use fkooman\OAuth\Client\Exception\AuthorizeException;
use fkooman\OAuth\Client\Exception\CallbackException;
use fkooman\OAuth\Client\SessionStorage;
use fkooman\OAuth\Client\StorageInterface;
use Guzzle\Http\Client;
use Symfony\Component\HttpFoundation\RedirectResponse;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;

class OAuthClient
{
    /**
     * @var StorageInterface
     */
    private $tokenStorage;
    /**
     * @var Client
     */
    private $httpClient;
    /**
     * @var ClientConfigInterface
     */
    private $clientConfig;

    /**
     * @var Context
     */
    private $context;

    /**
     * @var Api
     */
    private $api;

    /**
     * @var Callback
     */
    private $callback;

    /**
     * @var string
     */
    private $authserverUrl;

    /**
     * @param string $appName The name of this application (must be unique within a domain)
     * @param string $authServerUrl The URL to the base path of Authserver
     * @param string $clientId OAuth client ID
     * @param string $clientSecret OAuth client secret
     * @param array $scopes OAuth scopes to request
     * @param Client|null $client Guzzle client to use. A new client will be created if null
     */
    public function __construct($appName, $authServerUrl, $clientId, $clientSecret, array $scopes, Client $client = null)
    {
        $this->authserverUrl = $authServerUrl;
        $this->clientConfig = new ClientConfig([
            'authorize_endpoint' => $authServerUrl.'/oauth/v2/auth',
            'token_endpoint' => $authServerUrl.'/oauth/v2/token',
            'client_id' => $clientId,
            'client_secret' => $clientSecret,
        ]);
        $this->tokenStorage = new SessionStorage();
        $this->httpClient = $client?:new Client();
        $this->context = new Context("u", $scopes);
        $this->api = new Api($appName, $this->clientConfig, $this->tokenStorage, $this->httpClient);
        $this->callback = new Callback($appName, $this->clientConfig, $this->tokenStorage, $this->httpClient);
    }

    /**
     * Gets the current access token
     * @return bool|\fkooman\OAuth\Client\AccessToken
     */
    private function getAccessToken()
    {
        return $this->api->getAccessToken($this->context);
    }

    /**
     * Gets the user data when a user is logged in
     * @throws BearerErrorResponseException When OAuth authentication failed
     * @return array|null The user data when a user is authenticated, or null when there is no user authenticated
     */
    public function getUserData()
    {
        $accessToken = $this->getAccessToken();
        if(!$accessToken)
            return null;
        $this->httpClient->addSubscriber(new BearerAuth($accessToken->getAccessToken()));

        try {
            $response = $this->httpClient->get($this->authserverUrl . '/api/user.json')
                ->send()->json();
            return $response;
        } catch(BearerErrorResponseException $ex) {
            $this->api->deleteAccessToken($this->context);
            $this->api->deleteRefreshToken($this->context);
            throw $ex;
        }
    }

    /**
     * Checks if someone is currently authenticated
     * @return bool
     */
    public function isAuthenticated() {
        return !!$this->getAccessToken();
    }

    /**
     * Tries to authenticate a user
     * @param Request $request The request
     * @return \Exception|RedirectResponse Returns an exception when authentication fails, or a redirect response when a redirect is required
     * @throws \fkooman\OAuth\Client\Exception\ApiException
     */
    public function tryAuthentication(Request $request) {
        $this->clientConfig->setRedirectUri($request->getUri());
        if($request->query->has('code')||$request->query->has('error')) {
            try {
                $this->callback->handleCallback($request->query->all());
            } catch (AuthorizeException $ex) {
                return $ex;
            } catch (CallbackException $ex) {
                return $ex;
            }
        }
        if($request->query->has('code'))
            return new RedirectResponse($request->duplicate([])->getRequestUri());

        if(!$this->getAccessToken())
            return new RedirectResponse($this->api->getAuthorizeUri($this->context));
    }
}
