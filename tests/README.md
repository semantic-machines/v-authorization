# V-Authorization Test Suite

This document describes the comprehensive test suite for the v-authorization library, organized into modular test files for better maintainability and navigation.

## Test Structure

The test suite is organized into the following modules:

### 1. Unit Tests
Located in `src/` files, these test individual functions and components:
- **Access Control Lists (ACLRecord)**: Testing record creation, manipulation, and edge cases
- **Trace System**: Testing authorization tracing and debugging functionality  
- **Common Utilities**: Testing constants, helper functions, and data structures

### 2. Integration Tests
Located in `tests/` directory, organized by functionality:

#### **Integration Scenarios (`tests/integration_scenarios.rs`)**
JavaScript platform compatibility tests - these tests mirror specific JavaScript tests from the Veda platform:
- `test_basic_group_authorization_workflow` - Complete group authorization workflow (mirrors test011.js)
- `test_individual_as_group_scenario` - Individual documents acting as groups (mirrors test015.js)
- `test_range_query_patterns` - Range query authorization patterns (mirrors test030.js)
- `test_permission_filters_complete_scenario` - Complete permission filter workflow (mirrors test031.js)
- `test_nested_groups_with_restrictions_scenario` - Complex nested groups with restrictions (mirrors test016.js-test018.js patterns)
- `test_group_membership_with_access_levels_scenario` - Different access levels for group members
- `test_cyclic_groups_scenario` - Circular group dependency handling

These tests ensure exact compatibility between the Rust library and platform JavaScript implementation.

#### **Core Authorization (`tests/core_authorization.rs`)**
Basic authorization functionality and foundation patterns:
- `test_direct_permission_allow` - Direct user permissions that should be granted
- `test_direct_permission_deny` - Direct permissions that should be denied
- `test_group_based_permission` - Access through group membership
- `test_hierarchical_groups` - Multi-level group inheritance
- `test_object_groups` - Object membership in groups
- `test_combined_permissions` - Combination of direct and group permissions
- `test_all_resources_group` - Special ALL_RESOURCES group behavior
- `test_no_permissions` - Access attempts with no permissions defined
- `test_trace_functionality` - Authorization tracing capabilities
- `test_multiple_users_same_resource` - Multiple users accessing same resource
- `test_error_handling` - Invalid input and edge case handling
- `test_access_rights_constants` - Access right constant values
- `test_access_encoding_decoding` - Permission encoding/decoding
- `test_mock_storage_functionality` - Test storage implementation

- `test_authorization_with_empty_or_invalid_ids` - Invalid ID handling

#### **Group Management (`tests/group_management.rs`)**
Advanced group hierarchy and membership patterns:
- `test_complex_group_restrictions` - Limited access through group chains
- `test_multiple_group_paths` - Multiple paths to same resource through different groups

*Note: Several tests from this module were moved to `integration_scenarios.rs` for better platform compatibility organization*

#### **Permission Management (`tests/permission_management.rs`)**
Permission control and access management:
- `test_deny_permissions` - Access denial scenarios
- `test_negative_permissions` - Negative permission patterns
- `test_mixed_positive_negative_permissions` - Mixed permission scenarios
- `test_permission_removal` - Permission removal and access changes
- `test_group_permission_removal` - Group permission management
- `test_permission_counters` - Permission usage tracking
- `test_permission_drop_count` - Permission consumption patterns
- `test_individual_group_membership_removal` - Individual membership management

#### **Advanced Patterns (`tests/advanced_patterns.rs`)**
Advanced authorization patterns and complex scenarios:
- `test_complex_inheritance_pattern` - Multi-level inheritance chains
- `test_cross_document_access_pattern` - Cross-resource access patterns
- `test_multi_role_access_pattern` - Multiple role management
- `test_dynamic_group_resolution` - Dynamic group resolution
- `test_resource_hierarchy_pattern` - Resource hierarchy access
- `test_temporal_access_pattern` - Time-based access patterns

#### **Edge Cases (`tests/edge_cases.rs`)**
Boundary conditions and edge case handling:
- `test_empty_string_ids` - Empty ID handling
- `test_very_long_ids` - Long ID support
- `test_special_characters_in_ids` - Special character handling
- `test_zero_access_permissions` - Zero access scenarios
- `test_maximum_access_bits` - Maximum permission bits
- `test_self_referential_groups` - Self-referential group handling
- `test_unicode_ids` - Unicode ID support
- `test_mixed_case_sensitivity` - Case sensitivity testing
- `test_whitespace_in_ids` - Whitespace handling
- `test_large_permission_sets` - Large permission set handling
- `test_deep_group_nesting` - Deep group hierarchy testing

#### **Authorization Patterns (`tests/authorization_patterns.rs`)**
Complex authorization patterns and scenarios:
- `test_nested_groups_with_restrictions_and_cycles` - Complex nested groups with cycles (mirrors test019.js)
- `test_multiple_users_same_resource_batch_access` - Batch access patterns (mirrors test021.js)
- `test_admin_vs_user_access_patterns` - Admin and user role patterns from platform
- `test_group_membership_management` - Group membership lifecycle management

- `test_permission_subject_pattern` - Permission subject patterns (v-s:permissionSubject)
- `test_can_update_property_pattern` - Boolean property patterns (v-s:canUpdate)


#### **Realistic Scenarios (`tests/realistic_scenarios.rs`)**
Real-world authorization scenarios based on platform patterns:
- `test_document_lifecycle_multi_user` - Complete document lifecycle with multiple users
- `test_complex_group_structure_with_restrictions` - Complex group hierarchies with restrictions
- `test_membership_management_patterns` - Membership management lifecycle
- `test_platform_authentication_patterns` - Platform authentication patterns
- `test_document_author_permissions_realistic` - Realistic author permission scenarios
- `test_permission_subject_realistic` - Realistic permission subject usage
- `test_can_update_boolean_property` - Boolean property access control
- `test_temporal_access_patterns_realistic` - Realistic temporal access patterns

#### **Specialized Authorization (`tests/specialized_authorization.rs`)**
Specialized authorization functions and advanced scenarios:
- `test_module_waiting_patterns` - Module waiting and synchronization patterns
- `test_resource_type_patterns` - Resource type-based access control
- `test_membership_exclusive_patterns` - Exclusive membership patterns
- `test_ignore_exclusive_patterns` - Ignore exclusive patterns
- `test_permission_filter_patterns` - Fine-grained permission filter patterns
- `test_script_execution_patterns` - Dynamic script execution authorization
- `test_combined_authorization_patterns` - Comprehensive authorization scenario

*Note: `test_range_query_patterns` was moved to `integration_scenarios.rs` for better platform compatibility organization*

#### **Permission Filters (`tests/permission_filters.rs`)**
Advanced permission filtering functionality:
- `test_permission_filters_various_rights` - Filter behavior with different right combinations
- `test_multiple_permission_filters` - Multiple filters on same resource
- `test_permission_filter_lifecycle` - Filter creation and deletion lifecycle
- `test_permission_filter_with_trace` - Filter behavior with explicit tracing

*Note: The main test `test_permission_filters_complete` was moved to `integration_scenarios.rs` as `test_permission_filters_complete_scenario`*

**Key Features:**
- **Permission Filters** - Restrict access to resources based on filter conditions
- **Filter Resources** - Associate filters with specific resource identifiers
- **Filter Lifecycle** - Create, apply, and delete filters dynamically
- **Filtered Permissions** - Grant permissions that bypass filter restrictions
- **Platform Compatibility** - Exact behavior matching with JavaScript test031.js

#### **Enhanced MockStorage Features**
The MockStorage implementation now includes:
- **Permission Filters** - `add_permission_filter()`, `delete_permission_filter()`
- **Filtered Permissions** - `add_right_with_filter()` for permissions with filter bypass
- **Filter-Aware Testing** - All test helper functions now consider active filters
- **Effective Rights Calculation** - `get_effective_rights()` applies filter restrictions
- **Filter Lifecycle Management** - Complete filter creation, application, and deletion

#### **JavaScript Test Compatibility**
The authorization tests provide exact compatibility with platform JavaScript tests:
- **test011.js** → `test_basic_group_authorization_workflow` - Complete group authorization workflow
- **test015.js** → `test_individual_as_group_scenario` - Individual documents as groups
- **test030.js** → `test_range_query_patterns` - Range query authorization patterns
- **test031.js** → `test_permission_filters_complete_scenario` - Complete permission filter workflow
- **test016.js-test018.js** → `test_nested_groups_with_restrictions_scenario` - Complex nested group patterns

Additional platform compatibility features:
- **v-s:PermissionFilter** → `PermissionFilter` struct with same semantics
- **v-s:useFilter** → `add_right_with_filter()` method
- **v-s:deleted** → `delete_permission_filter()` and `delete_permission()` methods
- **Filter Resource Linking** → Same filter resource association patterns

This ensures the Rust authorization library behaves identically to the platform's JavaScript implementation for all authorization scenarios.

### 3. Enhanced Test Utilities
Located in `tests/common/mod.rs`:
- **MockStorage**: Enhanced test implementation of Storage trait
- **Constants**: Test access right constants (READ, WRITE, UPDATE, DELETE, etc.)
- **Helper Functions**: Enhanced helpers mirroring platform patterns
- **Platform Helpers**: Functions mirroring JavaScript helpers.js patterns:
  - `test_success_read/test_fail_read` - Success/failure testing patterns
  - `test_success_update/test_fail_update` - Update testing patterns
  - `check_rights_success/check_rights_fail` - Rights verification patterns
  - `add_right/add_to_group/remove_from_group` - Permission management
  - `get_admin_ticket/get_user1_ticket/get_user2_ticket` - User simulation
  - `create_test_document/create_test_group` - Resource creation utilities
  - `wait_module/remove_individual` - Platform operation simulation

## Key Test Patterns

### Access Rights
Tests cover all combinations of access rights:
- **CREATE (1)**: Object creation permissions
- **READ (2)**: Object reading permissions  
- **UPDATE (4)**: Object modification permissions
- **DELETE (8)**: Object deletion permissions
- **FULL_ACCESS (15)**: All permissions combined

### Group Hierarchies
Tests validate complex organizational structures:
- Simple user → group → resource chains
- Multi-level hierarchies (user → dept → division → company)
- Cross-group memberships and restrictions
- Circular dependency handling

### Permission Inheritance
Tests verify proper permission flow:
- Direct user permissions
- Group-inherited permissions
- Object group memberships
- Effective permission calculation with restrictions

### Platform-Specific Patterns
Tests based on real platform usage:
- Document lifecycle management
- User authentication patterns (admin, user1, user2)
- Permission subjects (v-s:permissionSubject)
- Boolean properties (v-s:canUpdate)
- Temporal access patterns
- Module synchronization (m_acl, m_scripts, m_fulltext_indexer)
- Special groups (v-s:AllResourcesGroup)
- Membership exclusivity (v-s:isExclusive, v-s:ignoreExclusive)

### Edge Cases
Comprehensive edge case coverage:
- Empty or invalid IDs
- Non-existent users/resources
- Circular group dependencies
- Permission conflicts and resolution
- Access right encoding/decoding

## Running Tests

### All Tests
```bash
cargo test --no-default-features
```

### Specific Modules
```bash
# Core authorization tests
cargo test --test core_authorization --no-default-features

# Group management tests  
cargo test --test group_management --no-default-features

# Permission management tests
cargo test --test permission_management --no-default-features

# Advanced patterns tests
cargo test --test advanced_patterns --no-default-features

# Edge cases tests
cargo test --test edge_cases --no-default-features

# Authorization patterns tests
cargo test --test authorization_patterns --no-default-features

# Realistic scenarios tests
cargo test --test realistic_scenarios --no-default-features

# Specialized authorization tests
cargo test --test specialized_authorization --no-default-features

# Permission filters tests
cargo test --test permission_filters --no-default-features

# Unit tests only
cargo test --lib --no-default-features
```

### Individual Tests
```bash
# Specific test by name
cargo test test_nested_groups_with_restrictions_and_cycles --no-default-features

# Tests matching pattern
cargo test platform --no-default-features
```

### Platform-Specific Test Patterns
```bash
# Integration scenarios - tests that mirror specific JavaScript platform tests
cargo test --test integration_scenarios --no-default-features                   # all platform compatibility tests
cargo test test_basic_group_authorization_workflow --no-default-features         # mirrors test011.js
cargo test test_individual_as_group_scenario --no-default-features              # mirrors test015.js
cargo test test_range_query_patterns --no-default-features                      # mirrors test030.js
cargo test test_permission_filters_complete_scenario --no-default-features      # mirrors test031.js
cargo test test_nested_groups_with_restrictions_scenario --no-default-features  # mirrors test016.js-test018.js patterns
cargo test test_group_membership_with_access_levels_scenario --no-default-features
cargo test test_cyclic_groups_scenario --no-default-features
```

## Test Coverage Summary

The current test suite provides comprehensive coverage of:
- ✅ **Basic Authorization** - Direct and group-based permissions
- ✅ **Group Hierarchies** - Multi-level and complex structures  
- ✅ **Core Functionality** - All basic authorization patterns
- ✅ **Permission Management** - Access control and permission handling
- ✅ **Advanced Patterns** - Complex authorization scenarios
- ✅ **Platform Integration** - Real-world platform usage patterns
- ✅ **Realistic Scenarios** - Complete workflow testing
- ✅ **Veda Platform Specific** - Platform-specific patterns and behaviors
- ✅ **Permission Filters** - Advanced permission filtering (test031.js compatibility)
- ✅ **Edge Cases** - Invalid inputs, boundary conditions, and stress testing

**Total Tests: unit + integration**

### Platform Integration Features
- ✅ **JavaScript Test Mirroring** - Tests mirror platform JavaScript tests
- ✅ **Real User Scenarios** - Admin, user1, user2 patterns from platform
- ✅ **Document Lifecycle** - Complete create/read/update/delete cycles
- ✅ **Module Synchronization** - Platform module waiting patterns
- ✅ **Special Groups** - AllResourcesGroup, exclusive membership patterns
- ✅ **Permission Subjects** - v-s:permissionSubject patterns
- ✅ **Boolean Properties** - v-s:canUpdate, v-s:isExclusive patterns
- ✅ **Temporal Access** - Time-based access control patterns
- ✅ **Search Patterns** - Cursor-based search authorization
- ✅ **Range Queries** - Date range and filter-based access

## Integration with Platform

The test suite now closely mirrors the patterns from the Veda platform's JavaScript tests located in `~/work/veda/source-web/tests/backend/`:

- **test019.js** → `test_nested_groups_with_restrictions_and_cycles`
- **test020.js** → `test_search_and_cursor_patterns`
- **test021.js** → `test_multiple_users_same_resource_batch_access`
- **test030.js** → `test_range_query_patterns`
- **test031.js** → `test_permission_filters_complete`
- **helpers.js** → Enhanced helper functions in `tests/common/mod.rs`

This ensures that the Rust authorization library behaves consistently with the platform's expectations and covers the same real-world scenarios.

## Test Structure Benefits

This modular structure makes it easy to:
- Navigate to specific test categories
- Add new tests in appropriate modules
- Maintain and update test documentation
- Run targeted test suites during development
- Verify platform compatibility
- Test real-world scenarios
- Validate edge cases and error conditions