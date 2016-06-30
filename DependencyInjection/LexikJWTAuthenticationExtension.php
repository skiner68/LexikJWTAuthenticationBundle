<?php

namespace Lexik\Bundle\JWTAuthenticationBundle\DependencyInjection;

use Symfony\Component\Config\FileLocator;
use Symfony\Component\DependencyInjection\ContainerBuilder;
use Symfony\Component\DependencyInjection\Loader\XmlFileLoader;
use Symfony\Component\DependencyInjection\Reference;
use Symfony\Component\HttpKernel\DependencyInjection\Extension;

/**
 * This is the class that loads and manages your bundle configuration.
 *
 * To learn more see {@link http://symfony.com/doc/current/cookbook/bundles/extension.html}
 */
class LexikJWTAuthenticationExtension extends Extension
{
    /**
     * {@inheritdoc}
     */
    public function load(array $configs, ContainerBuilder $container)
    {
        $configuration = new Configuration();
        $config        = $this->processConfiguration($configuration, $configs);

        $loader = new XmlFileLoader($container, new FileLocator(__DIR__.'/../Resources/config'));
        $loader->load('services.xml');

        $container->setParameter('lexik_jwt_authentication.private_key_path', $config['private_key_path']);
        $container->setParameter('lexik_jwt_authentication.public_key_path', $config['public_key_path']);
        $container->setParameter('lexik_jwt_authentication.pass_phrase', $config['pass_phrase']);
        $container->setParameter('lexik_jwt_authentication.token_ttl', $config['token_ttl']);
        $container->setParameter('lexik_jwt_authentication.user_identity_field', $config['user_identity_field']);

        $encoderConfig = $config['encoder'];
        $container->setAlias('lexik_jwt_authentication.encoder', $encoderConfig['service']);
        $container->setAlias(
            'lexik_jwt_authentication.key_loader',
            'lexik_jwt_authentication.key_loader.'.$encoderConfig['encryption_engine']
        );
        $container->setParameter('lexik_jwt_authentication.encoder.signature_algorithm', $encoderConfig['signature_algorithm']);
        $container->setParameter('lexik_jwt_authentication.encoder.encryption_engine', $encoderConfig['encryption_engine']);

        // JWTTokenAuthenticator (Guard)
        $jwtAuthenticatorId = 'lexik_jwt_authentication.security.guard.jwt_token_authenticator';
        $jwtAuthenticator   = $container->getDefinition($jwtAuthenticatorId);
        $extractorsConfig   = $config['token_extractors'];

        if ($extractorsConfig['authorization_header']['enabled']) {
            $authorizationHeaderExtractorId = 'lexik_jwt_authentication.extractor.authorization_header_extractor';
            $container
                ->getDefinition($authorizationHeaderExtractorId)
                ->replaceArgument(0, $extractorsConfig['authorization_header']['prefix'])
                ->replaceArgument(1, $extractorsConfig['authorization_header']['name']);

            $jwtAuthenticator->addMethodCall('addTokenExtractor', [new Reference($authorizationHeaderExtractorId)]);
        }

        if ($extractorsConfig['query_parameter']['enabled']) {
            $queryParameterExtractorId = 'lexik_jwt_authentication.extractor.query_parameter_extractor';
            $container
                ->getDefinition($queryParameterExtractorId)
                ->replaceArgument(0, $extractorsConfig['query_parameter']['name']);

            $jwtAuthenticator->addMethodCall('addTokenExtractor', [new Reference($queryParameterExtractorId)]);
        }

        if ($extractorsConfig['cookie']['enabled']) {
            $cookieExtractorId = 'lexik_jwt_authentication.extractor.cookie_extractor';
            $container
                ->getDefinition($cookieExtractorId)
                ->replaceArgument(0, $extractorsConfig['cookie']['name']);

            $jwtAuthenticator->addMethodCall('addTokenExtractor', [new Reference($cookieExtractorId)]);
        }

        $container->setAlias('lexik_jwt_authentication.jwt_token_authenticator', $jwtAuthenticatorId);
    }
}
