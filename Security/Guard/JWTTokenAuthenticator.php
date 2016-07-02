<?php

namespace Lexik\Bundle\JWTAuthenticationBundle\Security\Guard;

use Lexik\Bundle\JWTAuthenticationBundle\Encoder\JWTEncoderInterface;
use Lexik\Bundle\JWTAuthenticationBundle\Event\JWTAuthenticatedEvent;
use Lexik\Bundle\JWTAuthenticationBundle\Events;
use Lexik\Bundle\JWTAuthenticationBundle\Exception\JWTAuthenticationException;
use Lexik\Bundle\JWTAuthenticationBundle\Exception\JWTDecodeFailure\JWTDecodeFailureException;
use Lexik\Bundle\JWTAuthenticationBundle\Response\JWTAuthenticationFailureResponse;
use Lexik\Bundle\JWTAuthenticationBundle\Security\Authentication\Token\JWTUserToken;
use Lexik\Bundle\JWTAuthenticationBundle\Services\JWTManagerInterface;
use Lexik\Bundle\JWTAuthenticationBundle\TokenExtractor\TokenExtractorInterface;
use Symfony\Component\EventDispatcher\EventDispatcherInterface;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\Security\Core\Authentication\Token\TokenInterface;
use Symfony\Component\Security\Core\Exception\AuthenticationException;
use Symfony\Component\Security\Core\Exception\UsernameNotFoundException;
use Symfony\Component\Security\Core\User\UserInterface;
use Symfony\Component\Security\Core\User\UserProviderInterface;
use Symfony\Component\Security\Guard\AbstractGuardAuthenticator;

/**
 * JsonWebToken Authenticator (Symfony Guard implementation).
 *
 * Usage:
 *
 * <code>
 * // security.yml
 * firewalls:
 *     api:
 *         guard:
 *             authenticators:
 *                 'lexik_jwt_authentication.jwt_authenticator'
 *         # ...
 * # ...
 * </code>
 *
 * Thanks Ryan Weaver (@weaverryan) for having shown us the way after introduced the component.
 *
 * @see http://knpuniversity.com/screencast/symfony-rest4/jwt-guard-authenticator
 *
 * @author Nicolas Cabot <n.cabot@lexik.fr>
 * @author Robin Chalas <robin.chalas@gmail.com>
 */
class JWTTokenAuthenticator extends AbstractGuardAuthenticator
{
    /**
     * @var JWTManagerInterface
     */
    private $jwtManager;

    /**
     * @var EventDispatcherInterface
     */
    private $dispatcher;

    /**
     * @var string
     */
    private $userIdentityField;

    /**
     * @var TokenExtractorInterface[]
     */
    private $tokenExtractors = [];

    /**
     * @param JWTEncoderInterface $encoder
     */
    public function __construct(JWTManagerInterface $jwtManager, EventDispatcherInterface $dispatcher, $userIdentityField = 'username')
    {
        $this->jwtManager        = $jwtManager;
        $this->dispatcher        = $dispatcher;
        $this->userIdentityField = $userIdentityField;
    }

    /**
     * {@inheritdoc}
     */
    public function start(Request $request, AuthenticationException $authException = null)
    {
        return new JWTAuthenticationFailureResponse();
    }

    /**
     * {@inheritdoc}
     */
    public function getCredentials(Request $request)
    {
        if (false === ($jsonWebToken = $this->getTokenFromRequest($request))) {
            return;
        }

        $beforeAuthToken = new JWTUserToken();
        $beforeAuthToken->setRawToken($jsonWebToken);

        return $beforeAuthToken;
    }

    /**
     * Loads an user from a JWT Token.
     * 
     * {@inheritdoc}
     *
     * @throws JWTAuthenticationException If the token received cannot be decoded
     * @throws JWTAuthenticationException If an user cannot be loaded from the decoded token
     */
    public function getUser($beforeAuthToken, UserProviderInterface $userProvider)
    {
        try {
            if (!$payload = $this->jwtManager->decode($beforeAuthToken)) {
                throw JWTAuthenticationException::invalidToken();
            }
        } catch (JWTDecodeFailureException $e) {
            throw JWTAuthenticationException::invalidToken($e);
        }

        $identity = $this->getUserIdentityFromPayload($payload);

        try {
            $user = $userProvider->loadUserByUsername($identity);
        } catch (UsernameNotFoundException $e) {
            throw JWTAuthenticationException::invalidUser($identity, $this->userIdentityField);
        }

        $authToken = new JWTUserToken($user->getRoles());
        $authToken->setUser($user);
        $authToken->setRawToken($beforeAuthToken->getCredentials());

        $event = new JWTAuthenticatedEvent($payload, $authToken);
        $this->dispatcher->dispatch(Events::JWT_AUTHENTICATED, $event);

        return $user;
    }

    /**
     * {@inheritdoc}
     */
    public function checkCredentials($credentials, UserInterface $user)
    {
        return true;
    }

    /**
     * {@inheritdoc}
     */
    public function onAuthenticationFailure(Request $request, AuthenticationException $authException)
    {
        return new JWTAuthenticationFailureResponse($authException->getMessage());
    }

    /**
     * {@inheritdoc}
     */
    public function onAuthenticationSuccess(Request $request, TokenInterface $token, $providerKey)
    {
        return;
    }

    /**
     * {@inheritdoc}
     */
    public function supportsRememberMe()
    {
        return false;
    }

    public function addTokenExtractor(TokenExtractorInterface $extractor)
    {
        $this->tokenExtractors[] = $extractor;
    }

    /**
     * @param Request $request
     *
     * @return bool|string
     */
    private function getTokenFromRequest(Request $request)
    {
        foreach ($this->tokenExtractors as $extractor) {
            if ($token = $extractor->extract($request)) {
                return $token;
            }
        }

        return false;
    }

    /**
     * Returns the user identity from a given payload.
     *
     * @param array $payload
     *
     * @return string
     *
     * @throws JWTAuthenticationException If userIdentityField cannot be found as key of the payload
     */
    private function getUserIdentityFromPayload(array $payload)
    {
        if (isset($payload[$this->userIdentityField])) {
            return $payload[$this->userIdentityField];
        }

        throw JWTAuthenticationException::invalidPayload(
            sprintf('Unable to find a key corresponding to the configured user_identity_field ("%s") in the token payload')
        );
    }
}
