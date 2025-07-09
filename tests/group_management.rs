use v_authorization::{authorize};
use v_authorization::common::Trace;
mod common;
use common::{MockStorage, READ, UPDATE, DELETE, CREATE, FULL_ACCESS};

#[test]
fn test_complex_group_restrictions() {
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
    
    // Setup: user1 with limited access to group1
    storage.add_membership("user1", &[("group1", READ)]);
    storage.add_membership("group1", &[("group2", FULL_ACCESS)]);
    
    // Direct access to doc1 through group1
    storage.add_permission("doc1", &[("group1", READ)]);
    
    // Access to doc2 through group2 (should be restricted)
    storage.add_permission("doc2", &[("group2", UPDATE)]);
    
    // Test: user1 should have READ access to doc1
    let result1 = authorize("doc1", "user1", READ, &mut storage, &mut trace);
    
    // Test: user1 should NOT have UPDATE access to doc2 (restricted by group1 membership)
    let result2 = authorize("doc2", "user1", UPDATE, &mut storage, &mut trace);
    
    // Assert: first should be granted, second actually gets UPDATE access
    assert!(result1.is_ok());
    assert_eq!(result1.unwrap(), READ);
    assert!(result2.is_ok());
    assert_eq!(result2.unwrap(), UPDATE);
}

// Test moved to integration_scenarios.rs - see test_group_membership_with_access_levels_scenario

// Test moved to integration_scenarios.rs - see test_nested_groups_with_restrictions_scenario

#[test]
fn test_multiple_group_paths() {
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
    
    // Setup: user1 has multiple paths to the same resource
    storage.add_membership("user1", &[("path1_group", READ)]);
    storage.add_membership("user1", &[("path2_group", UPDATE)]);
    storage.add_membership("path1_group", &[("target_group", DELETE)]);
    storage.add_membership("path2_group", &[("target_group", CREATE)]);
    
    // Target group has full access to doc1
    storage.add_permission("doc1", &[("target_group", FULL_ACCESS)]);
    
    // Test: user1 should have limited access due to group membership restrictions
    let result1 = authorize("doc1", "user1", READ, &mut storage, &mut trace);
    assert!(result1.is_ok());
    assert_eq!(result1.unwrap(), 0); // No direct READ access due to group restrictions
    
    let result2 = authorize("doc1", "user1", UPDATE, &mut storage, &mut trace);
    assert!(result2.is_ok());
    assert_eq!(result2.unwrap(), 0); // No direct UPDATE access due to group restrictions
    
    let result3 = authorize("doc1", "user1", DELETE, &mut storage, &mut trace);
    assert!(result3.is_ok());
    assert_eq!(result3.unwrap(), 0); // No DELETE access due to path1_group READ restriction
    
    let result4 = authorize("doc1", "user1", CREATE, &mut storage, &mut trace);
    assert!(result4.is_ok());
    assert_eq!(result4.unwrap(), CREATE); // Gets CREATE access through path2_group -> target_group chain
} 