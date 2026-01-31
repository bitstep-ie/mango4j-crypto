# mango4j-utils - Examples

## Conformance with @Tolerate and @Reduce
```java
class Category {
    @Tolerate(min = 3, max = 3)
    private String code;

    @Reduce(max = 5)
    private String label;
}

Category category = new Category();
category.setCode("SQL Database");
category.setLabel("Payments Platform");

Conformer.conform(category);
```

## ObjectMutator with HTML escaping
```java
class Message {
    @Text
    private String body;
}

ObjectMutator mutator = new ObjectMutator()
    .on(Text.class, new HtmlEscapeMutator());

mutator.mutate(message);
```

## Masking utilities
```java
String maskedPan = MaskerFactory.getMasker(PanMasker.class).mask("5105105105105100");
String maskedId = new IdMasker("Y").mask("01234567890ABCDEF");
```

## URLGenerator
```java
String url = URLGenerator.ofURL("http://api.stage.bitstep.ie//mdes/")
    .path("consumer")
    .path("allocate")
    .param("limit", "100")
    .toString();
```

## MappingUtils
```java
Map<String, Object> payload = MappingUtils.fromObjectToMap(somePojo);
String json = MappingUtils.fromObjectToJson(somePojo);
```

## UUIDv7
```java
UUID id = new UUIDv7().generate();
```

## NamedScheduledExecutorBuilder
```java
ScheduledExecutorService executor = NamedScheduledExecutorBuilder.builder()
    .poolSize(4)
    .threadNamePrefix("crypto-retry")
    .daemon(true)
    .build();
```
