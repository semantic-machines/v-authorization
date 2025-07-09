//! Integration Scenarios Tests
//! 
//! This module consolidates all Rust tests that mirror specific JavaScript platform tests
//! from ~/work/veda/source-web/tests/backend/. These tests ensure exact compatibility 
//! between the Rust authorization library and the platform's JavaScript implementation.
//! 
//! ## JavaScript Test Mapping:
//! - test011.js → test_basic_group_authorization_workflow
//! - test015.js → test_individual_as_group_scenario  
//! - test030.js → test_range_query_patterns
//! - test031.js → test_permission_filters_complete_scenario

use v_authorization::{authorize};
use v_authorization::common::Trace;

mod common;
use common::{MockStorage, READ, UPDATE, DELETE, FULL_ACCESS};

/// Test basic group authorization workflow (mirrors test011.js)
/// 
/// JavaScript test011.js description:
/// "User1 stores individual, user2 should fail to read individual.
///  User1 adds individual to object group, user1 adds user2 to subject group.
///  User1 adds right [R] for subject group to object group, user2 should read individual.
///  User1 removes user2 from subject group, user2 should fail to read individual.
///  User1 removes individual, user1 should fail to read individual."
#[test]
fn test_basic_group_authorization_workflow() {
    let mut storage = MockStorage::new();
    
    // Get user tickets (simulating platform users)
    let user1 = MockStorage::get_user1_ticket();
    let user2 = MockStorage::get_user2_ticket();
    
    // Step 1: User1 creates document
    let new_test_doc1 = storage.create_test_document(user1, "test_doc");
    
    // Step 2: User1 can read document, user2 cannot
    assert!(storage.test_success_read(&new_test_doc1, user1));
    assert!(storage.test_fail_read(&new_test_doc1, user2));
    
    // Step 3: Create groups (simulating platform group URIs)
    let doc_group = storage.create_test_group("doc_group");
    let user_group = storage.create_test_group("user_group");
    
    // Step 4: Add document to object group
    storage.add_to_group(&doc_group, &new_test_doc1, FULL_ACCESS);
    
    // Step 5: Add user2 to subject group  
    storage.add_to_group(&user_group, user2, FULL_ACCESS);
    
    // Step 6: Grant READ right from subject group to object group
    storage.add_right(&user_group, &doc_group, READ);
    
    // Simulate module synchronization (m_acl module processing)
    assert!(storage.wait_module(2)); // m_acl = 2
    
    // Step 7: User2 can now read document through group chain
    // user2 -> user_group -> doc_group -> new_test_doc1
    assert!(storage.test_success_read(&new_test_doc1, user2));
    
    // Step 8: Remove user2 from subject group
    storage.remove_from_group(&user_group, user2);
    
    // Simulate module synchronization
    assert!(storage.wait_module(2)); // m_acl = 2
    
    // Step 9: User2 can no longer read document
    assert!(storage.test_fail_read(&new_test_doc1, user2));
    
    // Step 10: Remove document
    storage.remove_individual(&new_test_doc1);
    
    // Step 11: User1 can no longer read document (it's been removed)
    assert!(storage.test_fail_read(&new_test_doc1, user1));
}

/// Test individual as group scenario (mirrors test015.js)
/// 
/// JavaScript test015.js description:
/// "Individual as a group"
/// Tests the concept where an individual document can act as a group for authorization purposes.
#[test]
fn test_individual_as_group_scenario() {
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
    
    // Setup: user1 as individual is a "group" member of group1
    storage.add_membership("user1", &[("group1", READ)]);
    
    // user2 is member of user1 (using individual as group)
    storage.add_membership("user2", &[("user1", FULL_ACCESS)]);
    
    // group1 has UPDATE access to doc1
    storage.add_permission("doc1", &[("group1", UPDATE)]);
    
    // Test: user2 should have access through user1 -> group1 chain
    let result = authorize("doc1", "user2", UPDATE, &mut storage, &mut trace);
    
    // Assert: access denied (limited by user1's READ-only access to group1)
    assert!(result.is_ok());
    assert_eq!(result.unwrap(), 0);
}

/// Test range query patterns (mirrors test030.js)
/// 
/// Tests authorization patterns for range queries and batch operations
/// typically used for search results and paginated data access.
#[test]
fn test_range_query_patterns() {
    let mut storage = MockStorage::new();
    
    let user1 = MockStorage::get_user1_ticket();
    let admin = MockStorage::get_admin_ticket();
    
    // Create a range of documents
    let mut docs = Vec::new();
    for i in 1..=10 {
        let doc = storage.create_test_document(user1, &format!("range_doc_{}", i));
        docs.push(doc);
    }
    
    // Grant admin access to all documents
    for doc in &docs {
        storage.add_right(admin, doc, READ);
    }
    
    // Test range access
    for doc in &docs {
        assert!(storage.test_success_read(doc, admin));
        assert!(storage.test_success_read(doc, user1)); // Owner access
    }
    
    // Test non-owner access
    let user2 = MockStorage::get_user2_ticket();
    for doc in &docs {
        assert!(storage.test_fail_read(doc, user2));
    }
}

/// Test permission filters complete scenario (mirrors test031.js exactly)
/// 
/// JavaScript test031.js description:
/// "Check rights filter"
/// Tests the complete permission filter workflow including creation, application,
/// filtered permissions, and deletion of both permissions and filters.
#[test]
fn test_permission_filters_complete_scenario() {
    let mut storage = MockStorage::new();
    
    // Simulate tickets from JavaScript test
    let user1 = MockStorage::get_user1_ticket();
    let user2 = MockStorage::get_user2_ticket();  
    let _admin = MockStorage::get_admin_ticket();
    
    // Create test document (mirrors new_test_doc1 creation)
    let doc_uri = storage.create_test_document(user1, "test31");
    
    // Initial state: user1 (author) can read, user2 cannot
    assert!(storage.test_success_read(&doc_uri, user1));
    assert!(storage.test_fail_read(&doc_uri, user2));
    
    // Give user2 read and update rights (mirrors addRight call)
    storage.add_permission(&doc_uri, &[(user2, READ | UPDATE)]);
    
    // Both users should be able to read and update now
    assert!(storage.test_success_read(&doc_uri, user1));
    assert!(storage.test_success_update(&doc_uri, user1));
    assert!(storage.test_success_read(&doc_uri, user2));
    assert!(storage.test_success_update(&doc_uri, user2));
    
    // Create permission filter (mirrors new_permission_filter creation)
    let filter_id = "test31-pf:filter123";
    let filter_resource = "test31-pf:filter123xxx";
    
    // Filter allows only READ access (mirrors v-s:canRead: true)
    storage.add_permission_filter(filter_id, &doc_uri, filter_resource, READ);
    
    // After filter creation, both users should only be able to read (not update)
    assert!(storage.test_success_read(&doc_uri, user1));
    assert!(storage.test_fail_update(&doc_uri, user1));
    assert!(storage.test_success_read(&doc_uri, user2));
    assert!(storage.test_fail_update(&doc_uri, user2));
    
    // Admin grants user2 UPDATE permission with filter (mirrors addRight with filter)
    storage.add_right_with_filter(user2, &doc_uri, UPDATE, Some(filter_resource));
    
    // Now user1 still can't update (restricted by filter)
    // but user2 can update (has filtered permission)
    assert!(storage.test_fail_update(&doc_uri, user1));
    assert!(storage.test_success_update(&doc_uri, user2));
    
    // Delete the filtered permission (mirrors permission deletion)
    storage.delete_permission(user2, &doc_uri);
    
    // Add back the permission without filter for user2
    storage.add_permission(&doc_uri, &[(user2, READ | UPDATE)]);
    
    // user2 should no longer be able to update (no filtered permission)
    assert!(storage.test_fail_update(&doc_uri, user2));
    
    // Delete the filter itself (mirrors filter deletion)
    storage.delete_permission_filter(filter_id);
    
    // After filter deletion, user2 should regain update access
    assert!(storage.test_success_update(&doc_uri, user2));
    assert!(storage.test_success_update(&doc_uri, user1));
}

/// Test nested groups with restrictions (based on test016.js, test017.js, test018.js patterns)
/// 
/// Tests complex nested group hierarchies with various access restrictions,
/// similar to the patterns found in test016.js through test018.js.
#[test]
fn test_nested_groups_with_restrictions_scenario() {
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
    
    // Setup: nested groups with different access restrictions
    storage.add_membership("user1", &[("level1", READ)]);
    storage.add_membership("level1", &[("level2", UPDATE)]);
    storage.add_membership("level2", &[("level3", DELETE)]);
    
    // Different permissions at each level
    storage.add_permission("doc1", &[("level1", READ)]);
    storage.add_permission("doc2", &[("level2", UPDATE)]);
    storage.add_permission("doc3", &[("level3", DELETE)]);
    
    // Test: user1 should have READ access to doc1
    let result1 = authorize("doc1", "user1", READ, &mut storage, &mut trace);
    assert!(result1.is_ok());
    assert_eq!(result1.unwrap(), READ);
    
    // Test: user1 should have UPDATE access to doc2 (through level1 -> level2)
    let result2 = authorize("doc2", "user1", UPDATE, &mut storage, &mut trace);
    assert!(result2.is_ok());
    assert_eq!(result2.unwrap(), UPDATE);
    
    // Test: user1 should have DELETE access to doc3 (through full chain)
    let result3 = authorize("doc3", "user1", DELETE, &mut storage, &mut trace);
    assert!(result3.is_ok());
    assert_eq!(result3.unwrap(), DELETE);
}

/// Test group membership management with different access levels
/// 
/// Tests complex group membership scenarios where users have different
/// access levels to the same groups, reflecting real-world organizational structures.
#[test]
fn test_group_membership_with_access_levels_scenario() {
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
    
    // Setup: different users with different access levels to the same group
    storage.add_membership("user1", &[("shared_group", READ)]);
    storage.add_membership("user2", &[("shared_group", READ | UPDATE)]);
    storage.add_membership("user3", &[("shared_group", FULL_ACCESS)]);
    
    // Group has DELETE access to doc1
    storage.add_permission("doc1", &[("shared_group", DELETE)]);
    
    // Test: user1 should NOT have DELETE access (restricted by READ-only membership)
    let result1 = authorize("doc1", "user1", DELETE, &mut storage, &mut trace);
    assert!(result1.is_ok());
    assert_eq!(result1.unwrap(), 0);
    
    // Test: user2 should NOT have DELETE access (restricted by READ|UPDATE membership)
    let result2 = authorize("doc1", "user2", DELETE, &mut storage, &mut trace);
    assert!(result2.is_ok());
    assert_eq!(result2.unwrap(), 0);
    
    // Test: user3 should have DELETE access (FULL_ACCESS membership)
    let result3 = authorize("doc1", "user3", DELETE, &mut storage, &mut trace);
    assert!(result3.is_ok());
    assert_eq!(result3.unwrap(), DELETE);
}

/// Test cyclic groups scenario
/// 
/// Tests that the authorization system properly handles circular group dependencies
/// without infinite loops, which is a critical edge case for group-based authorization.
#[test]
fn test_cyclic_groups_scenario() {
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
    
    // Setup: cyclic group structure
    storage.add_membership("group1", &[("group2", FULL_ACCESS)]);
    storage.add_membership("group2", &[("group3", FULL_ACCESS)]);
    storage.add_membership("group3", &[("group1", FULL_ACCESS)]);
    
    // user1 is member of group1
    storage.add_membership("user1", &[("group1", FULL_ACCESS)]);
    
    // group2 has READ access to doc1
    storage.add_permission("doc1", &[("group2", READ)]);
    
    // Test: user1 should have access through group1 -> group2 chain
    let result = authorize("doc1", "user1", READ, &mut storage, &mut trace);
    
    // Assert: should be granted (cycles should be handled)
    assert!(result.is_ok());
    assert_eq!(result.unwrap(), READ);
} 