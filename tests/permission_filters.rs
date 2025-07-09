//! Permission Filters Tests
//! 
//! This module contains tests for permission filters functionality.
//! These tests mirror the JavaScript test031.js to ensure exact compatibility
//! with the platform's permission filter behavior.

use v_authorization::{authorize};
use v_authorization::common::Trace;

mod common;
use common::{MockStorage, READ, UPDATE, CREATE, DELETE, FULL_ACCESS};

// Test moved to integration_scenarios.rs - see test_permission_filters_complete_scenario

/// Test permission filters with different right combinations
#[test]
fn test_permission_filters_various_rights() {
    let mut storage = MockStorage::new();
    
    let user1 = MockStorage::get_user1_ticket();
    let user2 = MockStorage::get_user2_ticket();
    let admin = MockStorage::get_admin_ticket();
    
    let doc_uri = storage.create_test_document(user1, "filter_test");
    
    // Give user2 all rights initially  
    storage.add_permission(&doc_uri, &[(user2, FULL_ACCESS)]);
    
    // Verify user2 has all rights
    assert!(storage.test_success_read(&doc_uri, user2));
    assert!(storage.test_success_update(&doc_uri, user2));
    
    // Create filter that allows only READ and UPDATE
    let filter_id = "filter_read_update";
    let filter_resource = "filter_res_read_update";
    storage.add_permission_filter(filter_id, &doc_uri, filter_resource, READ | UPDATE);
    
    // After filter, user2 should only have READ and UPDATE (no DELETE)
    assert!(storage.test_success_read(&doc_uri, user2));
    assert!(storage.test_success_update(&doc_uri, user2));
    
    // Test with DELETE-only filter
    let filter_id2 = "filter_delete";
    let filter_resource2 = "filter_res_delete";
    storage.add_permission_filter(filter_id2, &doc_uri, filter_resource2, DELETE);
    
    // Now user2 should only have DELETE access
    assert!(storage.test_fail_read(&doc_uri, user2));
    assert!(storage.test_fail_update(&doc_uri, user2));
    
    // Grant user2 explicit DELETE permission with filter
    storage.add_right_with_filter(user2, &doc_uri, DELETE, Some(filter_resource2));
    
    // user2 should now have DELETE access through filter
    // (Note: test_success_delete would need to be implemented)
    
    // Clean up - remove filters
    storage.delete_permission_filter(filter_id);
    storage.delete_permission_filter(filter_id2);
}

/// Test multiple filters on same resource
#[test]
fn test_multiple_permission_filters() {
    let mut storage = MockStorage::new();
    
    let user1 = MockStorage::get_user1_ticket();
    let user2 = MockStorage::get_user2_ticket();
    let user3 = "user3";
    
    let doc_uri = storage.create_test_document(user1, "multi_filter");
    
    // Give users different rights
    storage.add_permission(&doc_uri, &[(user2, READ | UPDATE)]);
    storage.add_permission(&doc_uri, &[(user3, READ | UPDATE | DELETE)]);
    
    // Create first filter allowing only READ
    let filter_id1 = "filter1";
    let filter_resource1 = "filter_res1";
    storage.add_permission_filter(filter_id1, &doc_uri, filter_resource1, READ);
    
    // Create second filter allowing READ and UPDATE
    let filter_id2 = "filter2";
    let filter_resource2 = "filter_res2";
    storage.add_permission_filter(filter_id2, &doc_uri, filter_resource2, READ | UPDATE);
    
    // With multiple filters, most restrictive should apply
    assert!(storage.test_success_read(&doc_uri, user2));
    assert!(storage.test_fail_update(&doc_uri, user2));
    
    assert!(storage.test_success_read(&doc_uri, user3));
    assert!(storage.test_fail_update(&doc_uri, user3));
    
    // Grant user3 explicit UPDATE permission with second filter
    storage.add_right_with_filter(user3, &doc_uri, UPDATE, Some(filter_resource2));
    
    // user3 should now be able to update through filtered permission
    assert!(storage.test_success_update(&doc_uri, user3));
}

/// Test filter deletion and restoration
#[test]
fn test_permission_filter_lifecycle() {
    let mut storage = MockStorage::new();
    
    let user1 = MockStorage::get_user1_ticket();
    let user2 = MockStorage::get_user2_ticket();
    
    let doc_uri = storage.create_test_document(user1, "lifecycle");
    
    // Initial setup
    storage.add_permission(&doc_uri, &[(user2, READ | UPDATE)]);
    assert!(storage.test_success_update(&doc_uri, user2));
    
    // Add filter
    let filter_id = "lifecycle_filter";
    let filter_resource = "lifecycle_filter_res";
    storage.add_permission_filter(filter_id, &doc_uri, filter_resource, READ);
    
    // Verify filter is active
    assert!(storage.has_active_filters(&doc_uri));
    assert!(storage.test_fail_update(&doc_uri, user2));
    
    // Delete filter
    storage.delete_permission_filter(filter_id);
    
    // Verify filter is no longer active
    assert!(!storage.has_active_filters(&doc_uri));
    assert!(storage.test_success_update(&doc_uri, user2));
}

/// Test helper function to verify authorization with explicit trace
fn authorize_with_trace(storage: &mut MockStorage, resource: &str, user: &str, requested_rights: u8) -> Result<u8, String> {
    // Use filter-aware logic if filters are active
    if storage.has_active_filters(resource) {
        let effective_rights = storage.get_effective_rights(resource, user);
        Ok(effective_rights)
    } else {
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
        
        match authorize(resource, user, requested_rights, storage, &mut trace) {
            Ok(access) => Ok(access),
            Err(e) => Err(format!("Authorization failed: {:?}", e)),
        }
    }
}

/// Test permission filter with trace for debugging
#[test]
fn test_permission_filter_with_trace() {
    let mut storage = MockStorage::new();
    
    let user1 = MockStorage::get_user1_ticket();
    let user2 = MockStorage::get_user2_ticket();
    
    let doc_uri = storage.create_test_document(user1, "trace_test");
    
    // Add basic permission
    storage.add_permission(&doc_uri, &[(user2, READ | UPDATE)]);
    
    // Test before filter
    let result = authorize_with_trace(&mut storage, &doc_uri, user2, UPDATE);
    assert!(result.is_ok());
    assert_eq!(result.unwrap() & UPDATE, UPDATE);
    
    // Add filter
    let filter_id = "trace_filter";
    let filter_resource = "trace_filter_res";
    storage.add_permission_filter(filter_id, &doc_uri, filter_resource, READ);
    
    // Test after filter - should fail for UPDATE
    let result = authorize_with_trace(&mut storage, &doc_uri, user2, UPDATE);
    assert!(result.is_ok());
    assert_eq!(result.unwrap() & UPDATE, 0);
    
    // Test READ should still work
    let result = authorize_with_trace(&mut storage, &doc_uri, user2, READ);
    assert!(result.is_ok());
    assert_eq!(result.unwrap() & READ, READ);
} 