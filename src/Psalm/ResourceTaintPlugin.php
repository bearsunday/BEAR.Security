<?php

declare(strict_types=1);

namespace BEAR\Security\Psalm;

use Composer\InstalledVersions;
use LogicException;
use Psalm\Plugin\PluginEntryPointInterface;
use Psalm\Plugin\RegistrationInterface;
use SimpleXMLElement;

use function preg_match;
use function sprintf;
use function version_compare;

/**
 * Psalm plugin for BEAR.Sunday ResourceObject taint analysis
 *
 * Marks all parameters of on* methods (onGet, onPost, etc.) in ResourceObject
 * subclasses as taint sources, enabling security analysis through call_user_func_array.
 *
 * Configuration in psalm.xml:
 * <pluginClass class="BEAR\Security\Psalm\ResourceTaintPlugin">
 *     <targets>
 *         <target>Page</target>
 *         <target>App</target>
 *     </targets>
 * </pluginClass>
 */
class ResourceTaintPlugin implements PluginEntryPointInterface
{
    public function __invoke(RegistrationInterface $registration, ?SimpleXMLElement $config = null): void
    {
        // Composer's runtime API; a dev, unresolvable, or uninstalled Psalm version skips the guard.
        if (InstalledVersions::isInstalled('vimeo/psalm')) {
            $psalmVersion = InstalledVersions::getPrettyVersion('vimeo/psalm');
            if ($psalmVersion !== null && preg_match('/^(\d+\.\d+\.\d+)/', $psalmVersion, $matches) === 1) {
                $numericVersion = $matches[1];
                if (version_compare($numericVersion, '7.3.0', '<')) {
                    throw new LogicException(sprintf('bear/security requires Psalm 7.3 or later, including a Psalm installed under vendor-bin; found %s.', $psalmVersion));
                }

                if (version_compare($numericVersion, '8.0.0', '>=')) {
                    throw new LogicException(sprintf('bear/security supports Psalm 7.x only, including a Psalm installed under vendor-bin; found %s.', $psalmVersion));
                }
            }
        }

        if ($config !== null && isset($config->targets->target)) {
            $targets = [];
            foreach ($config->targets->target as $target) {
                $targets[] = (string) $target;
            }
            if ($targets !== []) {
                ResourceTaintHandler::$targets = $targets;
            }
        }

        class_exists(ResourceTaintHandler::class);
        $registration->registerHooksFromClass(ResourceTaintHandler::class);
    }
}
