# mango4j-collections - Documentation

## MapBuilder
Fluent builder for nested maps.

```java
MapBuilder<String, Object> builder = MapBuilder.map();
builder.with("service", "payments");
builder.withPath("config", "db")
    .with("host", "localhost")
    .with("port", 5432);

Map<String, Object> map = builder.build();
```

## ListBuilder
Fluent builder for lists, with optional concrete list implementations.

```java
List<String> names = ListBuilder.<String>list(new LinkedList<>())
    .add("Hello")
    .add("Dolly")
    .build();
```

## MapUtils
Utilities for merging, replacing, copying, and list-wrapping map values.

```java
Map<String, String> input = MapBuilder.<String, String>map()
    .with("name", "java")
    .build();

Map<String, List<String>> output = MapUtils.entriesToList(input);
```

## CollectionReconciler
Reconciles a current collection against a desired collection using a key extractor.

```java
List<User> current = new ArrayList<>(List.of(new User("u1"), new User("u2")));
List<User> desired = List.of(new User("u2"), new User("u3"));

CollectionReconciler.reconcile(current, desired, User::id);
```

## ConcurrentCache
TTL-based cache with eviction and optional `AutoCloseable` cleanup.

```java
ScheduledExecutorService cleaner = Executors.newSingleThreadScheduledExecutor();
ConcurrentCache<String, String> cache = new ConcurrentCache<>(
    Duration.ofMinutes(10),
    Duration.ofMinutes(10),
    Duration.ofSeconds(5),
    Duration.ofMinutes(1),
    cleaner,
    Clock.systemUTC()
);

cache.put("token", "abc123");
String value = cache.get("token");
```
