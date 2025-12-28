<?php

declare(strict_types=1);

namespace BEAR\Security\Psalm;

use Psalm\Internal\DataFlow\DataFlowNode;
use Psalm\Internal\DataFlow\TaintSource;
use Psalm\Plugin\EventHandler\AfterFunctionLikeAnalysisInterface;
use Psalm\Plugin\EventHandler\Event\AfterFunctionLikeAnalysisEvent;
use Psalm\Storage\MethodStorage;
use Psalm\Type\TaintKindGroup;

use function str_contains;
use function str_starts_with;
use function strtolower;

class ResourceTaintHandler implements AfterFunctionLikeAnalysisInterface
{
    /** @var list<string> */
    public static array $targets = ['Page', 'App'];

    public static function afterStatementAnalysis(AfterFunctionLikeAnalysisEvent $event): ?bool
    {
        $codebase = $event->getCodebase();

        if (!$codebase->taint_flow_graph) {
            return null;
        }

        $storage = $event->getFunctionlikeStorage();
        if (!$storage instanceof MethodStorage) {
            return null;
        }

        $method_name = $storage->cased_name ?? '';
        if (!str_starts_with($method_name, 'on')) {
            return null;
        }

        $class_name = $storage->defining_fqcln ?? '';
        if ($class_name === '') {
            return null;
        }

        // Check if class extends ResourceObject
        if (!$codebase->classExtends($class_name, 'BEAR\Resource\ResourceObject')) {
            if ($class_name !== 'BEAR\Resource\ResourceObject') {
                return null;
            }
        }

        // Check if class matches configured targets (Page/App)
        if (!self::matchesTargets($class_name)) {
            return null;
        }

        $method_id = $class_name . '::' . $method_name;
        $cased_method_id = $method_id;

        foreach ($storage->params as $offset => $param) {
            $arg_id = strtolower($method_id) . '#' . ($offset + 1);
            $label = $cased_method_id . '#' . ($offset + 1);

            $node = new DataFlowNode(
                $arg_id,
                $label,
                $param->location,
                null,
                TaintKindGroup::ALL_INPUT
            );

            $taint_source = TaintSource::fromNode($node);
            $codebase->taint_flow_graph->addSource($taint_source);
        }

        return null;
    }

    private static function matchesTargets(string $class_name): bool
    {
        foreach (self::$targets as $target) {
            // Check for \Resource\{Target}\ pattern in namespace
            if (str_contains($class_name, "\\Resource\\{$target}\\")) {
                return true;
            }
        }

        return false;
    }
}
