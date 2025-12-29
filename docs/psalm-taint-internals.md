# Psalm Taint Plugin Internals

Technical details for contributors and advanced users.

## Problem

BEAR.Sunday's `ResourceObject` methods (`onGet`, `onPost`, etc.) are invoked via `call_user_func_array`, which breaks Psalm's taint propagation chain. Standard taint analysis cannot recognize method parameters as external input.

## Solution

The plugin hooks into Psalm's analysis phase and manually registers method parameters as taint sources.

## Implementation

1. Implements `AfterFunctionLikeAnalysisInterface` to hook into method analysis
2. Checks if class extends `BEAR\Resource\ResourceObject` via `classExtends()`
3. Filters methods starting with `on` (onGet, onPost, onPut, onPatch, onDelete)
4. Creates `DataFlowNode` with `TaintKindGroup::ALL_INPUT` for each parameter
5. Registers `TaintSource` via `taint_flow_graph->addSource()`

## Key Classes

- `ResourceTaintPlugin` - Plugin entry point, handles configuration
- `ResourceTaintHandler` - Implements taint source registration logic

## Node ID Format

Psalm requires specific node ID format for taint tracking:

```php
$arg_id = strtolower($method_id) . '#' . ($offset + 1);
// e.g., "myvendor\myapp\resource\app\user::onget#1"
```

## Configuration

The plugin accepts `targets` configuration to filter which resource namespaces to analyze:

```xml
<pluginClass class="BEAR\Security\Psalm\ResourceTaintPlugin">
    <targets>
        <target>Page</target>
        <target>App</target>
    </targets>
</pluginClass>
```

This checks for `\Resource\{Target}\` pattern in the class namespace.

## Stubs

For packages without official taint annotations, stubs provide the annotations:

- `stubs/PDO.phpstub` - PDO taint sinks
- `stubs/AuraSql.phpstub` - Aura.Sql sinks and escapes
- `stubs/Qiq.phpstub` - Qiq HTML escape helpers

## References

- [Psalm Plugin Development](https://psalm.dev/docs/running_psalm/plugins/)
- [Psalm Security Analysis](https://psalm.dev/docs/security_analysis/)
- [Psalm Taint Sources](https://psalm.dev/docs/security_analysis/custom_taint_sources/)
