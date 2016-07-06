<?php

namespace Lexik\Bundle\JWTAuthenticationBundle\Tests\Security\Guard;

use Lexik\Bundle\JWTAuthenticationBundle\Event\JWTAuthenticatedEvent;
use Lexik\Bundle\JWTAuthenticationBundle\Events;
use Lexik\Bundle\JWTAuthenticationBundle\Security\Authentication\Token\BeforeAuthToken;
use Lexik\Bundle\JWTAuthenticationBundle\Security\Authentication\Token\JWTUserToken;
use Lexik\Bundle\JWTAuthenticationBundle\Security\Guard\JWTTokenAuthenticator;
use Lexik\Bundle\JWTAuthenticationBundle\Services\JWTManagerInterface;
use Lexik\Bundle\JWTAuthenticationBundle\TokenExtractor\TokenExtractorInterface;
use Symfony\Component\EventDispatcher\EventDispatcherInterface;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\Security\Core\User\UserInterface;
use Symfony\Component\Security\Core\User\UserProviderInterface;

class JWTTokenAuthenticatorTest extends \PHPUnit_Framework_TestCase
{
    public function testGetCredentials()
    {
        $userIdentityField = 'username';
        $payload           = [$userIdentityField => 'lexik'];
        $jwtManager        = $this->getJWTManagerMock();
        $dispatcher        = $this->getEventDispatcherMock();
        $extractor         = $this->getTokenExtractorMock('token');
        $request           = $this->getRequestMock();

        $jwtManager
            ->expects($this->once())
            ->method('decode')
            ->willReturn($payload);

        $authenticator = new JWTTokenAuthenticator($jwtManager, $dispatcher, $extractor, $userIdentityField);

        $this->assertInstanceOf(BeforeAuthToken::class, $authenticator->getCredentials($request));
    }

    public function testGetUser()
    {
        $userIdentityField = 'username';
        $payload           = [$userIdentityField => 'lexik'];
        $rawToken          = 'token';
        $userRoles         = ['ROLE_USER'];
        $decodedToken      = new BeforeAuthToken($rawToken);
        $decodedToken->setPayload($payload);

        $userMock = $this->getUserMock();
        $userMock
            ->expects($this->once())
            ->method('getRoles')
            ->willReturn($userRoles);

        $jwtUserToken = new JWTUserToken($userRoles);
        $jwtUserToken->setUser($userMock);
        $jwtUserToken->setRawToken($rawToken);

        $dispatcher = $this->getEventDispatcherMock();
        $dispatcher
            ->expects($this->once())
            ->method('dispatch')
            ->with(Events::JWT_AUTHENTICATED, new JWTAuthenticatedEvent($payload, $jwtUserToken));

        $userProvider = $this->getUserProviderMock();
        $userProvider
            ->expects($this->once())
            ->method('loadUserByUsername')
            ->with($payload[$userIdentityField])
            ->willReturn($userMock);

        $jwtManager = $this->getJWTManagerMock();
        $extractor  = $this->getTokenExtractorMock();

        $authenticator = new JWTTokenAuthenticator($jwtManager, $dispatcher, $extractor, $userIdentityField);

        $this->assertSame($userMock, $authenticator->getUser($decodedToken, $userProvider));
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

        if ($returnValue) {
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

    private function getUserMock()
    {
        return $this->getMockBuilder(UserInterface::class)
            ->disableOriginalConstructor()
            ->getMock();
    }
}
