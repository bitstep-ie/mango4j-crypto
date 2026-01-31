# mango4j-validation

## Overview
Jakarta validation helpers and reusable constraints.

## Architecture
- Constraint annotations: `@Type4UUID`, `@StrictType4UUID`, `@IsValidKebabCase`, `@IsValidDottedCase`.
- Validators: `KebabCaseValidator`, `DottedCaseValidator`, `IdentifierValidator`.
- `ValidationUtils` for programmatic validation and exception handling.

## How to use
### Gradle
```gradle
implementation("ie.bitstep.mango:mango4j-validation:VERSION")
```

### Maven
```xml
<dependency>
    <groupId>ie.bitstep.mango</groupId>
    <artifactId>mango4j-validation</artifactId>
    <version>VERSION</version>
</dependency>
```

## Example
```java
class CreateRequest {
    @Type4UUID
    private String requestId;

    @IsValidKebabCase
    private String slug;
}

ValidationUtils.validate(request);
```
