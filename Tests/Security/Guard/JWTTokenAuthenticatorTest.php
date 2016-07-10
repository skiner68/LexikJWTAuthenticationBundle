<?php

namespace Lexik\Bundle\JWTAuthenticationBundle\Tests\Security\Guard;

use Lexik\Bundle\JWTAuthenticationBundle\Event\JWTAuthenticatedEvent;
use Lexik\Bundle\JWTAuthenticationBundle\Event\JWTInvalidEvent;
use Lexik\Bundle\JWTAuthenticationBundle\Event\JWTNotFoundEvent;
use Lexik\Bundle\JWTAuthenticationBundle\Events;
use Lexik\Bundle\JWTAuthenticationBundle\Exception\JWTAuthenticationException;
use Lexik\Bundle\JWTAuthenticationBundle\Response\JWTAuthenticationFailureResponse;
use Lexik\Bundle\JWTAuthenticationBundle\Security\Authentication\Token\BeforeAuthToken;
use Lexik\Bundle\JWTAuthenticationBundle\Security\Authentication\Token\JWTUserToken;
use Lexik\Bundle\JWTAuthenticationBundle\Security\Guard\JWTTokenAuthenticator;
use Lexik\Bundle\JWTAuthenticationBundle\Services\JWTManagerInterface;
use Lexik\Bundle\JWTAuthenticationBundle\Tests\Stubs\User as AdvancedUserStub;
use Lexik\Bundle\JWTAuthenticationBundle\TokenExtractor\TokenExtractorInterface;
use Symfony\Component\EventDispatcher\EventDispatcherInterface;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\Security\Core\Exception\UsernameNotFoundException;
use Symfony\Component\Security\Core\User\UserProviderInterface;

class JWTTokenAuthenticatorTest extends \PHPUnit_Framework_TestCase
{
    public function testGetCredentials()
    {
        $userIdentityField = 'username';
        $payload           = [$userIdentityField => 'lexik'];

        $jwtManager = $this->getJWTManagerMock();
        $jwtManager
            ->expects($this->once())
            ->method('decode')
            ->willReturn($payload);

        $authenticator = new JWTTokenAuthenticator(
            $jwtManager,
            $this->getEventDispatcherMock(),
            $this->getTokenExtractorMock('token'),
            $userIdentityField
        );

        $this->assertInstanceOf(BeforeAuthToken::class, $authenticator->getCredentials($this->getRequestMock()));
    }

    /**
     * @expectedException        \Lexik\Bundle\JWTAuthenticationBundle\Exception\JWTAuthenticationException
     * @expectedExceptionMessage Invalid JWT Token
     */
    public function testGetCredentialsWithInvalidToken()
    {
        $userIdentityField = 'username';
        $payload           = [$userIdentityField => 'lexik'];

        (new JWTTokenAuthenticator(
            $this->getJWTManagerMock(),
            $this->getEventDispatcherMock(),
            $this->getTokenExtractorMock('token'),
            $userIdentityField
        ))->getCredentials($this->getRequestMock());
    }

    public function testGetCredentialsWithoutToken()
    {
        $userIdentityField = 'username';
        $payload           = [$userIdentityField => 'lexik'];

        $authenticator = new JWTTokenAuthenticator(
            $this->getJWTManagerMock(),
            $this->getEventDispatcherMock(),
            $this->getTokenExtractorMock(false),
            $userIdentityField
        );

        $this->assertNull($authenticator->getCredentials($this->getRequestMock()));
    }

    public function testGetUser()
    {
        $userIdentityField = 'username';
        $payload           = [$userIdentityField => 'lexik'];
        $rawToken          = 'token';
        $userRoles         = ['ROLE_USER'];

        $dispatcher = $this->getEventDispatcherMock();
        $userStub   = new AdvancedUserStub('lexik', 'password', 'user@gmail.com', $userRoles);

        $jwtUserToken = new JWTUserToken($userRoles);
        $jwtUserToken->setUser($userStub);
        $jwtUserToken->setRawToken($rawToken);

        $dispatcher
            ->expects($this->once())
            ->method('dispatch')
            ->with(Events::JWT_AUTHENTICATED, new JWTAuthenticatedEvent($payload, $jwtUserToken));

        $decodedToken = new BeforeAuthToken($rawToken);
        $decodedToken->setPayload($payload);

        $userProvider = $this->getUserProviderMock();
        $userProvider
            ->expects($this->once())
            ->method('loadUserByUsername')
            ->with($payload[$userIdentityField])
            ->willReturn($userStub);

        $authenticator = new JWTTokenAuthenticator(
            $this->getJWTManagerMock(),
            $dispatcher,
            $this->getTokenExtractorMock(),
            $userIdentityField
        );

        $this->assertSame($userStub, $authenticator->getUser($decodedToken, $userProvider));
    }

    /**
     * @expectedException        \Lexik\Bundle\JWTAuthenticationBundle\Exception\JWTAuthenticationException
     * @expectedExceptionMessage Unable to find a key corresponding to the configured user_identity_field ("username")
     */
    public function testGetUserWithInvalidPayload()
    {
        $decodedToken = new BeforeAuthToken('rawToken');
        $decodedToken->setPayload([]); // Empty payload

        (new JWTTokenAuthenticator(
            $this->getJWTManagerMock(),
            $this->getEventDispatcherMock(),
            $this->getTokenExtractorMock(),
            'username'
        ))->getUser($decodedToken, $this->getUserProviderMock());
    }

    /**
     * @expectedException        \Lexik\Bundle\JWTAuthenticationBundle\Exception\JWTAuthenticationException
     * @expectedExceptionMessage Unable to load a valid user with "username" "lexik"
     */
    public function testGetUserWithInvalidUser()
    {
        $userIdentityField = 'username';
        $payload           = [$userIdentityField => 'lexik'];

        $decodedToken = new BeforeAuthToken('rawToken');
        $decodedToken->setPayload($payload);

        $userProvider = $this->getUserProviderMock();
        $userProvider
            ->expects($this->once())
            ->method('loadUserByUsername')
            ->with($payload[$userIdentityField])
            ->will($this->throwException(new UsernameNotFoundException()));

        (new JWTTokenAuthenticator(
            $this->getJWTManagerMock(),
            $this->getEventDispatcherMock(),
            $this->getTokenExtractorMock(),
            $userIdentityField
        ))->getUser($decodedToken, $userProvider);
    }

    public function testOnAuthenticationFailureWithoutEventArg()
    {
        $request          = $this->getRequestMock();
        $authException    = new JWTAuthenticationException('Invalid JWT Token');
        $expectedResponse = new JWTAuthenticationFailureResponse('Invalid JWT Token');

        $dispatcher = $this->getEventDispatcherMock();
        $dispatcher
            ->expects($this->once())
            ->method('dispatch')
            ->with(
                Events::JWT_INVALID,
                new JWTInvalidEvent($request, $authException, $expectedResponse)
            );

        $authenticator = new JWTTokenAuthenticator(
            $this->getJWTManagerMock(),
            $dispatcher,
            $this->getTokenExtractorMock(),
            'username'
        );

        $response = $authenticator->onAuthenticationFailure($request, $authException);

        $this->assertEquals($expectedResponse, $response);
        $this->assertSame($expectedResponse->getMessage(), $response->getMessage());
    }

    public function testOnAuthenticationFailureWithJWTNotFoundEventArg()
    {
        $request          = $this->getRequestMock();
        $authException    = JWTAuthenticationException::tokenNotFound();
        $failureResponse  = new JWTAuthenticationFailureResponse($authException->getMessage());
        $event            = new JWTNotFoundEvent($request, $authException, $failureResponse);

        $authenticator = new JWTTokenAuthenticator(
            $this->getJWTManagerMock(),
            $this->getEventDispatcherMock(),
            $this->getTokenExtractorMock(),
            'username'
        );

        $response = $authenticator->onAuthenticationFailure($request, $authException, $event);

        $this->assertEquals($failureResponse, $response);
        $this->assertSame($failureResponse->getMessage(), $response->getMessage());
    }

    public function testStart()
    {
        $request          = $this->getRequestMock();
        $authException    = JWTAuthenticationException::tokenNotFound();
        $failureResponse  = new JWTAuthenticationFailureResponse($authException->getMessage());
        $event            = new JWTNotFoundEvent($request, $authException, $failureResponse);

        $dispatcher = $this->getEventDispatcherMock();
        $dispatcher
            ->expects($this->once())
            ->method('dispatch')
            ->with(
                Events::JWT_NOT_FOUND,
                new JWTNotFoundEvent($request, $authException, $failureResponse)
            );


        $authenticator = new JWTTokenAuthenticator(
            $this->getJWTManagerMock(),
            $dispatcher,
            $this->getTokenExtractorMock(),
            'username'
        );

        $response = $authenticator->start($request, $authException);

        $this->assertEquals($failureResponse, $response);
        $this->assertSame($failureResponse->getMessage(), $response->getMessage());
    }

    private function getJWTManagerMock()
    {
        return $this->getMockBuilder(JWTManagerInterface::class)
            ->disableOriginalConstructor()
            ->getMock();
    }

    private function getEventDispatcherMock()
    {
        return $this->getMockBuilder(EventDispatcherInterface::class)
            ->disableOriginalConstructor()
            ->getMock();
    }

    private function getTokenExtractorMock($returnValue = null)
    {
        $extractor = $this->getMockBuilder(TokenExtractorInterface::class)
            ->disableOriginalConstructor()
            ->getMock();

        if (null !== $returnValue) {
            $extractor
                ->expects($this->once())
                ->method('extract')
                ->willReturn($returnValue);
        }

        return $extractor;
    }

    private function getRequestMock()
    {
        return $this->getMockBuilder(Request::class)
            ->disableOriginalConstructor()
            ->getMock();
    }

    private function getUserProviderMock()
    {
        return $this->getMockBuilder(UserProviderInterface::class)
            ->disableOriginalConstructor()
            ->getMock();
    }
}
