# mango4j-collections - Examples

All examples use classes from `ie.bitstep.mango.collections`.

## MapBuilder
### Build a map
```java
Map<String, String> map = MapBuilder.<String, String>map().build();
```

### Build a map with specific implementation
```java
Map<String, String> map = MapBuilder.<String, String>map(new TreeMap<>()).build();
```

### Build a map and add items (nested)
```java
Map<String, Object> map = MapBuilder.<String, Object>map()
    .with("first", "Tom")
    .with("last", "Cruise")
    .with("address",
        MapBuilder.<String, String>map()
            .with("line1", "One South County")
            .with("line2", "Leopardstown")
            .build()
    )
    .build();
```

## ListBuilder
### Build a list
```java
List<String> list = ListBuilder.<String>list().build();
```

### Build a list with specific implementation
```java
List<String> list = ListBuilder.<String>list(new LinkedList<>()).build();
```

### Build a list and add items
```java
List<String> list = ListBuilder.<String>list()
    .add("Tom")
    .add("Cruise")
    .build();
```

### Build a list from an existing collection
```java
List<String> words = Arrays.asList("The", "cow", "jumped", "over", "the", "moon");
List<String> list = ListBuilder.<String>list().add(words).build();
```

## MapUtils
### Wrap values in lists
```java
Map<String, String> input = MapBuilder.<String, String>map()
    .with("name", "java")
    .build();

Map<String, List<String>> output = MapUtils.entriesToList(input);
```
