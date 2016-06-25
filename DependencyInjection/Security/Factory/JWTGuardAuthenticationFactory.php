<?php

namespace Lexik\Bundle\JWTAuthenticationBundle\DependencyInjection\Security\Factory;

use Symfony\Bundle\SecurityBundle\DependencyInjection\Security\Factory\GuardAuthenticationFactory;
use Symfony\Component\Config\Definition\Builder\NodeDefinition;
use Symfony\Component\DependencyInjection\ContainerBuilder;
use Symfony\Component\DependencyInjection\DefinitionDecorator;
use Symfony\Component\DependencyInjection\Reference;

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
        $jwtAuthenticatorId = 'security.guard.jwt_authenticator.'.$id;
        $jwtAuthenticator   = $container->setDefinition(
            $jwtAuthenticatorId,
            new DefinitionDecorator('lexik_jwt_authentication.security.guard.jwt_authenticator')
        );

        if ($config['authorization_header']['enabled']) {
            $authorizationHeaderExtractorId = 'lexik_jwt_authentication.extractor.authorization_header_extractor.'.$id;
            $container
                ->setDefinition($authorizationHeaderExtractorId, new DefinitionDecorator('lexik_jwt_authentication.extractor.authorization_header_extractor'))
                ->replaceArgument(0, $config['authorization_header']['prefix'])
                ->replaceArgument(1, $config['authorization_header']['name']);

            $jwtAuthenticator->addMethodCall('addTokenExtractor', [new Reference($authorizationHeaderExtractorId)]);
        }

        if ($config['query_parameter']['enabled']) {
            $queryParameterExtractorId = 'lexik_jwt_authentication.extractor.query_parameter_extractor.'.$id;
            $container
                ->setDefinition($queryParameterExtractorId, new DefinitionDecorator('lexik_jwt_authentication.extractor.query_parameter_extractor'))
                ->replaceArgument(0, $config['query_parameter']['name']);

            $jwtAuthenticator->addMethodCall('addTokenExtractor', [new Reference($queryParameterExtractorId)]);
        }

        if ($config['cookie']['enabled']) {
            $cookieExtractorId = 'lexik_jwt_authentication.extractor.cookie_extractor.'.$id;
            $container
                ->setDefinition($cookieExtractorId, new DefinitionDecorator('lexik_jwt_authentication.extractor.cookie_extractor'))
                ->replaceArgument(0, $config['cookie']['name']);

            $jwtAuthenticator->addMethodCall('addTokenExtractor', [new Reference($cookieExtractorId)]);
        }

        $config['authenticators'] = [$jwtAuthenticatorId];

        return parent::create($container, $id, $config, $userProvider, $defaultEntryPoint);
    }

    public function addConfiguration(NodeDefinition $node)
    {
        $node
            ->children()
                ->arrayNode('authorization_header')
                ->addDefaultsIfNotSet()
                    ->children()
                        ->booleanNode('enabled')
                            ->defaultTrue()
                        ->end()
                        ->scalarNode('prefix')
                            ->defaultValue('Bearer')
                        ->end()
                        ->scalarNode('name')
                            ->defaultValue('Authorization')
                        ->end()
                    ->end()
                ->end()
                ->arrayNode('cookie')
                ->addDefaultsIfNotSet()
                    ->children()
                        ->booleanNode('enabled')
                            ->defaultFalse()
                        ->end()
                        ->scalarNode('name')
                            ->defaultValue('BEARER')
                        ->end()
                    ->end()
                ->end()
                ->arrayNode('query_parameter')
                    ->addDefaultsIfNotSet()
                    ->children()
                        ->booleanNode('enabled')
                            ->defaultFalse()
                        ->end()
                        ->scalarNode('name')
                            ->defaultValue('bearer')
                        ->end()
                    ->end()
                ->end()
                ->booleanNode('throw_exceptions')
                    ->defaultFalse()
                ->end()
            ->end()
        ;

        parent::addConfiguration($node);
    }
}
