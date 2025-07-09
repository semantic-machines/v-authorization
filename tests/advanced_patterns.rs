use v_authorization::{authorize};
use v_authorization::common::Trace;

mod common;
use common::{MockStorage, READ, UPDATE, DELETE, FULL_ACCESS};

#[test]
fn test_resource_hierarchy_pattern() {
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
    
    // Setup: resource hierarchy where access to parent gives access to children
    storage.add_permission("project1", &[("user1", READ | UPDATE)]);
    storage.add_permission("project1/folder1", &[("user1", READ)]);
    storage.add_permission("project1/folder1/doc1", &[("user1", READ)]);
    
    // Test: access to different levels of hierarchy
    let result1 = authorize("project1", "user1", READ, &mut storage, &mut trace);
    assert!(result1.is_ok());
    assert_eq!(result1.unwrap(), READ);
    
    let result2 = authorize("project1/folder1", "user1", READ, &mut storage, &mut trace);
    assert!(result2.is_ok());
    assert_eq!(result2.unwrap(), READ);
    
    let result3 = authorize("project1/folder1/doc1", "user1", READ, &mut storage, &mut trace);
    assert!(result3.is_ok());
    assert_eq!(result3.unwrap(), READ);
}

#[test]
fn test_temporal_access_pattern() {
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
    
    // Setup: time-based access pattern simulation
    // In a real system, this would involve time-based permissions
    // For this test, we simulate different access at different "times"
    storage.add_permission("doc1", &[("user1", READ)]);
    
    // Test: basic temporal access (simplified)
    let result1 = authorize("doc1", "user1", READ, &mut storage, &mut trace);
    assert!(result1.is_ok());
    assert_eq!(result1.unwrap(), READ);
    
    // Simulate permission expiration by removing access
    storage.data.remove("Pdoc1");
    
    let result2 = authorize("doc1", "user1", READ, &mut storage, &mut trace);
    assert!(result2.is_ok());
    assert_eq!(result2.unwrap(), 0);
}

#[test]
fn test_conditional_access_pattern() {
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
    
    // Setup: conditional access based on multiple factors
    storage.add_membership("user1", &[("conditional_group", FULL_ACCESS)]);
    
    // Condition 1: user must be in conditional_group
    storage.add_permission("doc1", &[("conditional_group", READ)]);
    
    // Condition 2: additional permission required
    storage.add_permission("doc1", &[("user1", UPDATE)]);
    
    // Test: user gets combined permissions
    let result1 = authorize("doc1", "user1", READ, &mut storage, &mut trace);
    assert!(result1.is_ok());
    assert_eq!(result1.unwrap(), READ);
    
    let result2 = authorize("doc1", "user1", UPDATE, &mut storage, &mut trace);
    assert!(result2.is_ok());
    assert_eq!(result2.unwrap(), UPDATE);
    
    let result3 = authorize("doc1", "user1", READ | UPDATE, &mut storage, &mut trace);
    assert!(result3.is_ok());
    assert_eq!(result3.unwrap(), READ | UPDATE);
}

#[test]
fn test_cascading_permissions_pattern() {
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
    
    // Setup: cascading permissions where permission on one resource affects another
    storage.add_permission("parent_doc", &[("user1", FULL_ACCESS)]);
    storage.add_membership("child_doc", &[("parent_doc", FULL_ACCESS)]);
    
    // Test: access to child through parent
    let result1 = authorize("parent_doc", "user1", READ, &mut storage, &mut trace);
    assert!(result1.is_ok());
    assert_eq!(result1.unwrap(), READ);
    
    // User should have access to child_doc through parent_doc membership
    let result2 = authorize("child_doc", "user1", READ, &mut storage, &mut trace);
    assert!(result2.is_ok());
    assert_eq!(result2.unwrap(), READ);
}

#[test]
fn test_delegation_pattern() {
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
    
    // Setup: delegation pattern where user1 delegates access to user2
    storage.add_permission("doc1", &[("user1", FULL_ACCESS)]);
    
    // user1 delegates limited access to user2 through a delegation group
    storage.add_membership("user2", &[("delegation_from_user1", FULL_ACCESS)]);
    storage.add_membership("delegation_from_user1", &[("user1", READ)]);
    
    // Test: user2 gets limited access through delegation
    let result1 = authorize("doc1", "user2", READ, &mut storage, &mut trace);
    assert!(result1.is_ok());
    assert_eq!(result1.unwrap(), READ);
    
    // user2 should not have full access, only what was delegated
    let result2 = authorize("doc1", "user2", DELETE, &mut storage, &mut trace);
    assert!(result2.is_ok());
    assert_eq!(result2.unwrap(), 0);
} 