# mango4j-reflection

## Overview
Reflection helpers with cached metadata and property accessors.

## Architecture
- `ClassInfo` caches fields and methods for faster reflection.
- `PropertyAccessor` resolves getters/setters via conventions or annotations.
- `ReflectionUtils` offers convenient get/set operations and method lookups.

## How to use
### Gradle
```gradle
implementation("ie.bitstep.mango:mango4j-reflection:VERSION")
```

### Maven
```xml
<dependency>
    <groupId>ie.bitstep.mango</groupId>
    <artifactId>mango4j-reflection</artifactId>
    <version>VERSION</version>
</dependency>
```

## More
- [Examples](mango4j-reflection/examples.md)
