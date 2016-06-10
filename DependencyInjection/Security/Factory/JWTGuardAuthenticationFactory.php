<?php

namespace Lexik\Bundle\JWTAuthenticationBundle\DependencyInjection\Security\Factory;

use Symfony\Bundle\SecurityBundle\DependencyInjection\Security\Factory\GuardAuthenticationFactory;
use Symfony\Component\DependencyInjection\ContainerBuilder;

class JWTGuardAuthenticationFactory extends GuardAuthenticationFactory
{
    public function getPosition()
    {
        return 'pre_auth';
    }

    public function getKey()
    {
        return 'lexik_jwt_guard';
    }

    public function create(ContainerBuilder $container, $id, $config, $userProvider, $defaultEntryPoint)
    {
        $config['authenticators'] = ['lexik_jwt_authentication.security.guard.jwt_authenticator'];

        return parent::create($container, $id, $config, $userProvider, $defaultEntryPoint);
    }
}
