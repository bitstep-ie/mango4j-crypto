# mango4j-hibernate-proxy-resolver

## Overview
Hibernate proxy resolver used with `ObjectMutator` to unwrap lazy proxies.

## How to use
### Gradle
```gradle
implementation("ie.bitstep.mango:mango4j-hibernate-proxy-resolver:VERSION")
```

### Maven
```xml
<dependency>
    <groupId>ie.bitstep.mango</groupId>
    <artifactId>mango4j-hibernate-proxy-resolver</artifactId>
    <version>VERSION</version>
</dependency>
```

## Example
```java
ObjectMutator mutator = new ObjectMutator(new HibernateProxyResolver())
    .on(Text.class, new HtmlEscapeMutator());

mutator.mutate(entity);
```
