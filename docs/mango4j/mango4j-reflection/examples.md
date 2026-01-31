# mango4j-reflection - Examples

## Manipulate a property using a PropertyAccessor
```java
Profile profile = new Profile(...);
PropertyAccessor<String> accessor = new PropertyAccessor<>(Profile.class, "firstName");

accessor.set(profile, "Fred");
System.out.println(accessor.get(profile));
```

## Get a cached PropertyAccessor
```java
Profile profile = new Profile(...);
PropertyAccessor<String> accessor = ReflectionUtils
    .getClassInfo(Profile.class)
    .getPropertyAccessor("firstName");

accessor.set(profile, "Fred");
System.out.println(accessor.get(profile));
```

## Manipulate a property using ReflectionUtils
```java
Profile profile = new Profile(...);

ReflectionUtils.setField(profile, "firstName", "Fred");
System.out.println(ReflectionUtils.getField(profile, "firstName"));
```
