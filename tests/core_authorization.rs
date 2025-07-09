use v_authorization::{authorize};
use v_authorization::common::Trace;

mod common;
use common::{MockStorage, READ, UPDATE, FULL_ACCESS};

#[test]
fn test_direct_permission_allow() {
    let mut storage = MockStorage::new();
    let mut acl = String::new();
    let mut group = String::new();
    let mut info = String::new();
    let mut trace = Trace {
        acl: &mut acl,
        is_acl: false,
        group: &mut group,
        is_group: false,
        info: &mut info,
        is_info: false,
        str_num: 0,
    };
    
    // Setup: user1 has READ access to doc1
    storage.add_permission("doc1", &[("user1", READ)]);
    
    // Test: user1 requests READ access to doc1
    let result = authorize("doc1", "user1", READ, &mut storage, &mut trace);
    
    // Assert: should be granted
    assert!(result.is_ok());
    assert_eq!(result.unwrap(), READ);
}

#[test]
fn test_direct_permission_deny() {
    let mut storage = MockStorage::new();
    let mut acl = String::new();
    let mut group = String::new();
    let mut info = String::new();
    let mut trace = Trace {
        acl: &mut acl,
        is_acl: false,
        group: &mut group,
        is_group: false,
        info: &mut info,
        is_info: false,
        str_num: 0,
    };
    
    // Setup: user1 has READ access to doc1
    storage.add_permission("doc1", &[("user1", READ)]);
    
    // Test: user1 requests UPDATE access to doc1 (not granted)
    let result = authorize("doc1", "user1", UPDATE, &mut storage, &mut trace);
    
    // Assert: should return Ok(0) for denied access
    assert!(result.is_ok());
    assert_eq!(result.unwrap(), 0);
}

#[test]
fn test_group_based_permission() {
    let mut storage = MockStorage::new();
    let mut acl = String::new();
    let mut group = String::new();
    let mut info = String::new();
    let mut trace = Trace {
        acl: &mut acl,
        is_acl: false,
        group: &mut group,
        is_group: false,
        info: &mut info,
        is_info: false,
        str_num: 0,
    };
    
    // Setup: user1 is member of group1, group1 has READ access to doc1
    storage.add_membership("user1", &[("group1", FULL_ACCESS)]);
    storage.add_permission("doc1", &[("group1", READ)]);
    
    // Test: user1 requests READ access to doc1
    let result = authorize("doc1", "user1", READ, &mut storage, &mut trace);
    
    // Assert: should be granted through group membership
    assert!(result.is_ok());
    assert_eq!(result.unwrap(), READ);
}

#[test]
fn test_hierarchical_groups() {
    let mut storage = MockStorage::new();
    let mut acl = String::new();
    let mut group = String::new();
    let mut info = String::new();
    let mut trace = Trace {
        acl: &mut acl,
        is_acl: false,
        group: &mut group,
        is_group: false,
        info: &mut info,
        is_info: false,
        str_num: 0,
    };
    
    // Setup: user1 -> group1 -> group2 -> doc1
    storage.add_membership("user1", &[("group1", FULL_ACCESS)]);
    storage.add_membership("group1", &[("group2", FULL_ACCESS)]);
    storage.add_permission("doc1", &[("group2", READ)]);
    
    // Test: user1 requests READ access to doc1
    let result = authorize("doc1", "user1", READ, &mut storage, &mut trace);
    
    // Assert: should be granted through hierarchical membership
    assert!(result.is_ok());
    assert_eq!(result.unwrap(), READ);
}

#[test]
fn test_object_groups() {
    let mut storage = MockStorage::new();
    let mut acl = String::new();
    let mut group = String::new();
    let mut info = String::new();
    let mut trace = Trace {
        acl: &mut acl,
        is_acl: false,
        group: &mut group,
        is_group: false,
        info: &mut info,
        is_info: false,
        str_num: 0,
    };
    
    // Setup: doc1 is member of docgroup1, user1 has READ access to docgroup1
    storage.add_membership("doc1", &[("docgroup1", FULL_ACCESS)]);
    storage.add_permission("docgroup1", &[("user1", READ)]);
    
    // Test: user1 requests READ access to doc1
    let result = authorize("doc1", "user1", READ, &mut storage, &mut trace);
    
    // Assert: should be granted through object group membership
    assert!(result.is_ok());
    assert_eq!(result.unwrap(), READ);
}

#[test]
fn test_combined_permissions() {
    let mut storage = MockStorage::new();
    let mut acl = String::new();
    let mut group = String::new();
    let mut info = String::new();
    let mut trace = Trace {
        acl: &mut acl,
        is_acl: false,
        group: &mut group,
        is_group: false,
        info: &mut info,
        is_info: false,
        str_num: 0,
    };
    
    // Setup: user1 has READ access directly, UPDATE through group
    storage.add_permission("doc1", &[("user1", READ)]);
    storage.add_membership("user1", &[("group1", FULL_ACCESS)]);
    storage.add_permission("doc1", &[("group1", UPDATE)]);
    
    // Test: user1 requests READ+UPDATE access to doc1
    let result = authorize("doc1", "user1", READ | UPDATE, &mut storage, &mut trace);
    
    // Assert: should be granted (combination of direct and group permissions)
    assert!(result.is_ok());
    assert_eq!(result.unwrap(), READ | UPDATE);
}

#[test]
fn test_no_permissions() {
    let mut storage = MockStorage::new();
    let mut acl = String::new();
    let mut group = String::new();
    let mut info = String::new();
    let mut trace = Trace {
        acl: &mut acl,
        is_acl: false,
        group: &mut group,
        is_group: false,
        info: &mut info,
        is_info: false,
        str_num: 0,
    };
    
    // Setup: no permissions defined
    
    // Test: user1 requests READ access to doc1
    let result = authorize("doc1", "user1", READ, &mut storage, &mut trace);
    
    // Assert: should return Ok(0) for no permissions
    assert!(result.is_ok());
    assert_eq!(result.unwrap(), 0);
}

// Test moved to integration_scenarios.rs - see test_basic_group_authorization_workflow 