<?php

declare(strict_types=1);

namespace BEAR\Security\Psalm;

use Psalm\Internal\DataFlow\DataFlowNode;
use Psalm\Plugin\EventHandler\AfterFunctionLikeAnalysisInterface;
use Psalm\Plugin\EventHandler\Event\AfterFunctionLikeAnalysisEvent;
use Psalm\Storage\MethodStorage;
use Psalm\Type\TaintKind;

use function array_keys;
use function str_contains;
use function str_starts_with;

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
            return null;
        }

        // Check if class matches configured targets (Page/App)
        if (!self::matchesTargets($class_name)) {
            return null;
        }

        $cased_method_id = $class_name . '::' . $method_name;

        foreach (array_keys($storage->params) as $offset) {
            // Without a specialization location, this is the same unspecialized node the
            // method body itself uses for the parameter, so the source connects to its flow.
            $source = DataFlowNode::getForMethodArgument($cased_method_id, $offset, $storage)
                ->setTaints(TaintKind::ALL_INPUT);
            $codebase->taint_flow_graph->addSource($source);
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
