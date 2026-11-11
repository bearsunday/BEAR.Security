<?php

declare(strict_types=1);

namespace BEAR\Security\Psalm;

use LogicException;
use Psalm\Internal\VersionUtils;
use Psalm\Plugin\PluginEntryPointInterface;
use Psalm\Plugin\RegistrationInterface;
use SimpleXMLElement;

use function sprintf;
use function strtok;
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
        // composer's conflict cannot reach a Psalm installed in a separate project such as vendor-bin
        $psalmVersion = (string) strtok(VersionUtils::getPsalmVersion(), '@');
        if (version_compare($psalmVersion, '7.3.0', '<')) {
            throw new LogicException(sprintf('bear/security requires Psalm 7.3 or later, including a Psalm installed under vendor-bin; found %s.', $psalmVersion));
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
