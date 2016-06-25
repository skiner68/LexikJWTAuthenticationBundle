<?php

namespace Lexik\Bundle\JWTAuthenticationBundle\Security\Guard;

use Lexik\Bundle\JWTAuthenticationBundle\Encoder\JWTEncoderInterface;
use Lexik\Bundle\JWTAuthenticationBundle\Event\JWTAuthenticatedEvent;
use Lexik\Bundle\JWTAuthenticationBundle\Events;
use Lexik\Bundle\JWTAuthenticationBundle\Exception\JWTDecodeFailure\JWTDecodeFailureException;
use Lexik\Bundle\JWTAuthenticationBundle\Response\JWTAuthenticationFailureResponse;
use Lexik\Bundle\JWTAuthenticationBundle\Security\Authentication\Token\JWTUserToken;
use Lexik\Bundle\JWTAuthenticationBundle\TokenExtractor\TokenExtractorInterface;
use Symfony\Component\EventDispatcher\EventDispatcherInterface;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\Security\Core\Authentication\Token\TokenInterface;
use Symfony\Component\Security\Core\Exception\AuthenticationException;
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
 * Or if your firewall has only one guard authenticator, use:
 *
 * <code>
 * firewalls:
 *     api:
 *         lexik_jwt_guard: ~
 *     # ...
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
     * @var JWTEncoderInterface
     */
    protected $encoder;

    /**
     * @var EventDispatcherInterface
     */
    protected $dispatcher;

    /**
     * @var TokenExtractorInterface[]
     */
    protected $tokenExtractors = [];

    /**
     * @param JWTEncoderInterface $encoder
     */
    public function __construct(JWTEncoderInterface $encoder, EventDispatcherInterface $dispatcher)
    {
        $this->encoder    = $encoder;
        $this->dispatcher = $dispatcher;
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
        if (false === ($jsonWebToken = $this->extractToken($request))) {
            return;
        }

        return $jsonWebToken;
    }

    /**
     * {@inheritdoc}
     */
    public function getUser($token, UserProviderInterface $userProvider)
    {
        try {
            if (!$payload = $this->encoder->decode($token)) {
                throw $this->createAuthenticationException();
            }
        } catch (JWTDecodeFailureException $e) {
            throw $this->createAuthenticationException($e);
        }

        $user = $userProvider->loadUserByUsername($payload['username']); // TODO: replace 'username' by userIdentityField

        $authToken = new JWTUserToken($user->getRoles());
        $authToken->setUser($user);
        $authToken->setRawToken($token);

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
    protected function extractToken(Request $request)
    {
        foreach ($this->tokenExtractors as $extractor) {
            if (($token = $extractor->extract($request))) {
                return $token;
            }
        }

        return false;
    }

    /**
     * @param \Exception $previous
     *
     * @return AuthenticationException
     */
    private function createAuthenticationException(JWTDecodeFailureException $previous = null)
    {
        $message = (null === $previous) ? 'Invalid JWT Token' : $previous->getMessage();

        return new AuthenticationException($message, 401, $previous);
    }
}
