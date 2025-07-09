# v-authorization

Rust library for access control and authorization with support for complex group hierarchies and flexible permission systems.

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Version](https://img.shields.io/badge/version-0.4.0-blue.svg)](https://github.com/semantic-machines/v_authorization)

## Description

`v_authorization` is a powerful authorization library designed to check user access rights to resources. The library supports:

- **User groups** with hierarchical structure
- **Object groups** for resource organization  
- **Permission inheritance** through multi-level hierarchies
- **Exclusive rights** for special access cases
- **Access filtering** with dynamic restrictions
- **Detailed tracing** of decision-making process
- **Caching** for performance optimization

## Key Features

### Access Permission Types
- **Create (C)** - resource creation
- **Read (R)** - data reading
- **Update (U)** - modifying existing data
- **Delete (D)** - resource deletion
- **Deny permissions** - explicit access denial

### Group-based Authorization
- Users can belong to multiple groups
- Groups can be nested within other groups
- Rights are inherited through group hierarchies
- Support for exclusive groups for special cases

### Object Groups
- Resources can belong to object groups
- Permissions are set on object groups
- Support for global `AllResourcesGroup`

## Quick Start

### Adding to Project

```toml
[dependencies]
v_authorization = "0.4.0"
```

### Basic Usage

```rust
use v_authorization::{authorize, Storage, Trace};

// Implement Storage trait for your database
struct MyStorage;
impl Storage for MyStorage {
    fn get(&mut self, key: &str) -> io::Result<Option<String>> {
        // Your implementation for data retrieval
    }
    
    fn decode_rec_to_rights(&self, src: &str, result: &mut Vec<ACLRecord>) -> (bool, Option<DateTime<Utc>>) {
        // Your implementation for decoding rights
    }
    
    // ... other methods
}

// Check access
let mut storage = MyStorage;
let mut trace = Trace { /* ... */ };

let access = authorize(
    "document123",           // Resource ID
    "user456",              // User ID
    2,                      // Requested rights (Read = 2)
    &mut storage,           // Storage implementation
    &mut trace              // Tracing (optional)
)?;

if access & 2 == 2 {
    println!("Read access granted");
} else {
    println!("Access denied");
}
```

### Tracing for Debugging

```rust
use v_authorization::trace;

let trace_info = trace(
    "document123",
    "user456", 
    2,
    &mut storage
)?;

if let Some(trace_json) = trace_info.finalize() {
    println!("Detailed trace:\n{}", trace_json);
}
```

## Architecture

### Working Process
1. **Find user groups** - determine all groups the user belongs to
2. **Find object groups** - determine groups the requested resource belongs to
3. **Check permissions** - match rights between user and object groups
4. **Apply filters** - apply additional access restrictions
5. **Return result** - final access rights as a bitmask

### Data Format

The library uses the following prefixes for storage keys:
- `P` - permissions (Permissions)
- `M` - group membership (Membership)  
- `F` - access filters (Filters)

## Documentation

- **[Authorization Algorithm](doc/auth-algorithm-doc.md)** - detailed logic description
- **[Developer Documentation](doc/dev-doc.md)** - technical documentation
- **[JavaScript Implementation](doc/authorization.js)** - reference JS implementation
- **[Tests](tests/README.md)** - test coverage description

## Performance

- Caching support to minimize database queries
- Optimization of recursive queries through group hierarchies
- Recursion depth limits to prevent infinite loops
- Efficient bitwise arithmetic for permission handling

## Security

- Explicit handling of exclusive rights
- Input data validation
- Overflow protection for deep recursion
- Support for deny permissions

## Compatibility

- **Rust**: 2021 edition
- **Dependencies**: chrono, chrono-tz, serde_json

## License

This project is distributed under the [MIT](LICENSE) license.

## Developers

- [itiu](mailto:ValeriyBushenev@gmail.com)
- [muller95](mailto:muller95@yandex.ru)

## Repository

[https://github.com/semantic-machines/v_authorization](https://github.com/semantic-machines/v_authorization) 