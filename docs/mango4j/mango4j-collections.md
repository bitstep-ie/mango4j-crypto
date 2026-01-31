# mango4j-collections

## Overview
Common collections utilities for map/list construction, map operations, reconciliation, and caching.

## Architecture
- Builders: `MapBuilder` and `ListBuilder` for fluent construction.
- Utilities: `MapUtils` for merge/replace/copy and path creation.
- Reconciliation: `CollectionReconciler` for current vs desired collections.
- Caching: `ConcurrentCache` with TTL and eviction support.

## How to use
### Gradle
```gradle
implementation("ie.bitstep.mango:mango4j-collections:VERSION")
```

### Maven
```xml
<dependency>
    <groupId>ie.bitstep.mango</groupId>
    <artifactId>mango4j-collections</artifactId>
    <version>VERSION</version>
</dependency>
```

## More
- [Documentation](mango4j-collections/documentation.md)
- [Examples](mango4j-collections/examples.md)
