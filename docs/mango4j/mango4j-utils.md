# mango4j-utils

## Overview
General-purpose utilities used across mango4j modules.

## Architecture
- Conformance and mutation: `ObjectMutator`, `Conformer`, `@Reduce`, `@Tolerate`, `@Text`.
- Masking: `Masker` implementations, `MaskerFactory`, `MaskingUtils`.
- Date/time: `DateUtils`, `CalendarUtils`, `Proximity`, `MovingClock`.
- Mapping: `MappingUtils` for object-to-map/JSON conversion.
- URLs and formatting: `URLGenerator`, `QueryParam`, `MapFormat`.
- Threading and entities: `NamedScheduledExecutorBuilder`, `EntityToStringBuilder`.

## How to use
### Gradle
```gradle
implementation("ie.bitstep.mango:mango4j-utils:VERSION")
```

### Maven
```xml
<dependency>
    <groupId>ie.bitstep.mango</groupId>
    <artifactId>mango4j-utils</artifactId>
    <version>VERSION</version>
</dependency>
```

## More
- [Examples](mango4j-utils/examples.md)
