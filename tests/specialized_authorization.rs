//! Specialized Authorization Tests
//! 
//! This module contains tests for specialized authorization functions and advanced scenarios.
//! These tests cover specific authorization features, special groups, exclusive access patterns,
//! and complex authorization workflows.

// Specialized authorization tests use mock storage helpers mainly

mod common;
use common::{MockStorage, READ, UPDATE, FULL_ACCESS};

/// Test module waiting patterns for authorization system modules
#[test]
fn test_module_waiting_patterns() {
    let mut storage = MockStorage::new();
    
    let user1 = MockStorage::get_user1_ticket();
    let doc = storage.create_test_document(user1, "test_doc");
    
    // Simulate module constants for authorization system
    let m_acl = 2;
    let m_fulltext_indexer = 4;
    let m_scripts = 16;
    
    // Test waiting for modules (in tests, always returns true)
    assert!(storage.wait_module(m_acl));
    assert!(storage.wait_module(m_fulltext_indexer));
    assert!(storage.wait_module(m_scripts));
    
    // Test document access after module operations
    assert!(storage.test_success_read(&doc, user1));
    assert!(storage.test_success_update(&doc, user1));
    
    // Test document removal with module waiting
    storage.remove_individual(&doc);
    assert!(storage.wait_module(m_acl));
    assert!(storage.wait_module(m_scripts));
    
    // After removal, access should fail
    assert!(storage.test_fail_read(&doc, user1));
}

/// Test resource type patterns based on RDF types
#[test]
fn test_resource_type_patterns() {
    let mut storage = MockStorage::new();
    
    let user1 = MockStorage::get_user1_ticket();
    let user2 = MockStorage::get_user2_ticket();
    
    // Create documents with different types
    let resource_doc = storage.create_test_document(user1, "rdfs:Resource");
    let membership_doc = storage.create_test_document(user1, "v-s:Membership");
    let permission_doc = storage.create_test_document(user1, "v-s:Permission");
    
    // Create type-based groups
    let resource_group = storage.create_test_group("ResourceTypeGroup");
    let membership_group = storage.create_test_group("MembershipTypeGroup");
    
    // Grant type-based access
    storage.add_right(&resource_group, &resource_doc, READ);
    storage.add_right(&membership_group, &membership_doc, READ | UPDATE);
    
    // Add user2 to type groups
    storage.create_test_membership(user2, &resource_group, FULL_ACCESS);
    storage.create_test_membership(user2, &membership_group, FULL_ACCESS);
    
    // Test type-based access
    assert!(storage.test_success_read(&resource_doc, user2));
    assert!(storage.test_fail_update(&resource_doc, user2)); // Only read access
    
    assert!(storage.test_success_read(&membership_doc, user2));
    assert!(storage.test_success_update(&membership_doc, user2));
    
    // permission_doc should not be accessible to user2
    assert!(storage.test_fail_read(&permission_doc, user2));
}

/// Test v-s:Membership exclusive patterns
#[test]
fn test_membership_exclusive_patterns() {
    let mut storage = MockStorage::new();
    
    let user1 = MockStorage::get_user1_ticket();
    let user2 = MockStorage::get_user2_ticket();
    
    // Create groups and documents
    let exclusive_group = storage.create_test_group("ExclusiveGroup");
    let regular_group = storage.create_test_group("RegularGroup");
    let doc = storage.create_test_document(user1, "test_doc");
    
    // Create membership with exclusive access (simulated)
    storage.create_test_membership(user2, &exclusive_group, FULL_ACCESS);
    
    // Grant exclusive group access to document
    storage.add_right(&exclusive_group, &doc, READ);
    
    // Test exclusive access
    assert!(storage.test_success_read(&doc, user2));
    
    // Test that regular group access works normally
    storage.create_test_membership(user1, &regular_group, FULL_ACCESS);
    storage.add_right(&regular_group, &doc, UPDATE);
    
    // Both users should have their respective access
    assert!(storage.test_success_read(&doc, user2));
    assert!(storage.test_success_update(&doc, user1));
}

/// Test v-s:ignoreExclusive patterns
#[test]
fn test_ignore_exclusive_patterns() {
    let mut storage = MockStorage::new();
    
    let user1 = MockStorage::get_user1_ticket();
    let user2 = MockStorage::get_user2_ticket();
    
    // Create groups
    let exclusive_group = storage.create_test_group("ExclusiveGroup");
    let ignore_exclusive_group = storage.create_test_group("IgnoreExclusiveGroup");
    let doc = storage.create_test_document(user1, "test_doc");
    
    // Setup exclusive access
    storage.create_test_membership(user2, &exclusive_group, FULL_ACCESS);
    storage.add_right(&exclusive_group, &doc, READ);
    
    // Setup ignore exclusive access
    storage.create_test_membership(user1, &ignore_exclusive_group, FULL_ACCESS);
    storage.add_right(&ignore_exclusive_group, &doc, UPDATE);
    
    // Test both users can access despite exclusive setup
    assert!(storage.test_success_read(&doc, user2));
    assert!(storage.test_success_update(&doc, user1));
}

// Test moved to integration_scenarios.rs - see test_range_query_patterns

/// Test permission filter patterns
#[test]
fn test_permission_filter_patterns() {
    let mut storage = MockStorage::new();
    
    let user1 = MockStorage::get_user1_ticket();
    let user2 = MockStorage::get_user2_ticket();
    
    // Create document with filter
    let doc = storage.create_test_document(user1, "filtered_doc");
    
    // Add filter to document
    storage.add_filter(&doc, &[("filter_condition", READ)]);
    
    // Add user2 to filter condition
    storage.create_test_membership(user2, "filter_condition", FULL_ACCESS);
    
    // Grant user2 access to document
    storage.add_right(user2, &doc, READ);
    
    // Test filtered access
    assert!(storage.test_success_read(&doc, user2));
    assert!(storage.test_success_read(&doc, user1)); // Owner access
}

/// Test script execution patterns for authorization
#[test]
fn test_script_execution_patterns() {
    let mut storage = MockStorage::new();
    
    let user1 = MockStorage::get_user1_ticket();
    let script_user = "script_executor";
    
    // Create script-protected document
    let doc = storage.create_test_document(user1, "script_protected");
    
    // Grant script executor access
    storage.add_right(script_user, &doc, READ | UPDATE);
    
    // Test script execution access
    assert!(storage.test_success_read(&doc, script_user));
    assert!(storage.test_success_update(&doc, script_user));
    
    // Test owner retains access
    assert!(storage.test_success_read(&doc, user1));
    assert!(storage.test_success_update(&doc, user1));
}

/// Test combined authorization patterns with multiple features
#[test]
fn test_combined_authorization_patterns() {
    let mut storage = MockStorage::new();
    
    let admin = MockStorage::get_admin_ticket();
    let user1 = MockStorage::get_user1_ticket();
    let user2 = MockStorage::get_user2_ticket();
    
    // Create complex document structure
    let doc = storage.create_test_document(user1, "complex_doc");
    
    // Create multiple groups and roles
    let admin_group = storage.create_test_group("AdminGroup");
    let user_group = storage.create_test_group("UserGroup");
    let special_group = storage.create_test_group("SpecialGroup");
    
    // Complex membership structure
    storage.create_test_membership(admin, &admin_group, FULL_ACCESS);
    storage.create_test_membership(user1, &user_group, FULL_ACCESS);
    storage.create_test_membership(user2, &user_group, FULL_ACCESS);
    storage.create_test_membership(user2, &special_group, FULL_ACCESS);
    
    // Complex permissions
    storage.add_right(&admin_group, &doc, FULL_ACCESS);
    storage.add_right(&user_group, &doc, READ);
    storage.add_right(&special_group, &doc, UPDATE);
    
    // Test combined access
    assert!(storage.check_rights_success(&doc, admin, FULL_ACCESS));
    assert!(storage.check_rights_success(&doc, user1, READ));
    assert!(storage.check_rights_success(&doc, user2, READ | UPDATE));
    
    // Test access restrictions
    // user1 is the author, so they can UPDATE their own document
    assert!(storage.check_rights_success(&doc, user1, UPDATE));
    assert!(storage.check_rights_fail(&doc, user2, FULL_ACCESS));
} 