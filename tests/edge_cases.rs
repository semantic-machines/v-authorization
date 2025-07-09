use v_authorization::{authorize};
use v_authorization::common::Trace;

mod common;
use common::{MockStorage, READ, UPDATE, DELETE, FULL_ACCESS};

#[test]
fn test_very_long_ids() {
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
    
    // Test: very long IDs should be handled
    let long_id = "a".repeat(1000);
    let long_user = "u".repeat(1000);
    
    storage.add_permission(&long_id, &[(&long_user, READ)]);
    
    let result = authorize(&long_id, &long_user, READ, &mut storage, &mut trace);
    assert!(result.is_ok());
    assert_eq!(result.unwrap(), READ);
}

#[test]
fn test_special_characters_in_ids() {
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
    
    // Test: special characters in IDs
    let special_doc = "doc@#$%^&*()_+{}[]|;':\",./<>?";
    let special_user = "user!@#$%^&*";
    
    storage.add_permission(special_doc, &[(special_user, READ)]);
    
    let result = authorize(special_doc, special_user, READ, &mut storage, &mut trace);
    assert!(result.is_ok());
    assert_eq!(result.unwrap(), READ);
}

#[test]
fn test_zero_access_permissions() {
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
    
    // Test: zero access permissions should be handled
    storage.add_permission("doc1", &[("user1", 0)]);
    
    let result = authorize("doc1", "user1", READ, &mut storage, &mut trace);
    assert!(result.is_ok());
    // Zero access should result in no permissions
    assert_eq!(result.unwrap(), 0);
}

#[test]
fn test_maximum_access_bits() {
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
    
    // Test: high access bits should work with basic permissions
    storage.add_permission("doc1", &[("user1", FULL_ACCESS)]);
    
    // Test: basic permissions should work
    let result = authorize("doc1", "user1", READ, &mut storage, &mut trace);
    assert!(result.is_ok());
    assert_eq!(result.unwrap(), READ);
    
    let result = authorize("doc1", "user1", UPDATE, &mut storage, &mut trace);
    assert!(result.is_ok());
    assert_eq!(result.unwrap(), UPDATE);
    
    let result = authorize("doc1", "user1", DELETE, &mut storage, &mut trace);
    assert!(result.is_ok());
    assert_eq!(result.unwrap(), DELETE);
}

#[test]
fn test_unicode_ids() {
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
    
    // Test: unicode characters in IDs
    let unicode_doc = "документ_тест_🔒";
    let unicode_user = "пользователь_тест_👤";
    
    storage.add_permission(unicode_doc, &[(unicode_user, READ)]);
    
    let result = authorize(unicode_doc, unicode_user, READ, &mut storage, &mut trace);
    assert!(result.is_ok());
    assert_eq!(result.unwrap(), READ);
}

#[test]
fn test_mixed_case_sensitivity() {
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
    
    // Test: case sensitivity in IDs
    let doc_lower = "doc_test";
    let doc_upper = "DOC_TEST";
    let user_lower = "user_test";
    let user_upper = "USER_TEST";
    
    storage.add_permission(doc_lower, &[(user_lower, READ)]);
    storage.add_permission(doc_upper, &[(user_upper, READ)]);
    
    // Test: exact case matches should work
    let result1 = authorize(doc_lower, user_lower, READ, &mut storage, &mut trace);
    assert!(result1.is_ok());
    assert_eq!(result1.unwrap(), READ);
    
    let result2 = authorize(doc_upper, user_upper, READ, &mut storage, &mut trace);
    assert!(result2.is_ok());
    assert_eq!(result2.unwrap(), READ);
    
    // Test: case mismatches should fail
    let result3 = authorize(doc_lower, user_upper, READ, &mut storage, &mut trace);
    assert!(result3.is_ok());
    assert_eq!(result3.unwrap(), 0);
    
    let result4 = authorize(doc_upper, user_lower, READ, &mut storage, &mut trace);
    assert!(result4.is_ok());
    assert_eq!(result4.unwrap(), 0);
}

#[test]
fn test_whitespace_in_ids() {
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
    
    // Test: whitespace in IDs
    let doc_with_spaces = "doc with spaces";
    let user_with_tabs = "user\twith\ttabs";
    let user_with_newlines = "user\nwith\nnewlines";
    
    storage.add_permission(doc_with_spaces, &[(user_with_tabs, READ)]);
    storage.add_permission(doc_with_spaces, &[(user_with_newlines, UPDATE)]);
    
    let result1 = authorize(doc_with_spaces, user_with_tabs, READ, &mut storage, &mut trace);
    assert!(result1.is_ok());
    assert_eq!(result1.unwrap(), READ);
    
    let result2 = authorize(doc_with_spaces, user_with_newlines, UPDATE, &mut storage, &mut trace);
    assert!(result2.is_ok());
    assert_eq!(result2.unwrap(), UPDATE);
}

#[test]
fn test_large_permission_sets() {
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
    
    // Test: large number of permissions
    let doc = "doc1";
    let mut permissions = Vec::new();
    
    // Create 1000 users with permissions
    for i in 0..1000 {
        let user = format!("user{}", i);
        permissions.push((user.clone(), READ));
    }
    
    // Add all permissions at once
    let permission_refs: Vec<(&str, u8)> = permissions.iter()
        .map(|(user, access)| (user.as_str(), *access))
        .collect();
    storage.add_permission(doc, &permission_refs);
    
    // Test: authorization should work for all users
    for i in 0..10 { // Test only first 10 to avoid slow tests
        let user = format!("user{}", i);
        let result = authorize(doc, &user, READ, &mut storage, &mut trace);
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), READ);
    }
    
    // Test: non-existent user should fail
    let result = authorize(doc, "non_existent_user", READ, &mut storage, &mut trace);
    assert!(result.is_ok());
    assert_eq!(result.unwrap(), 0);
}

#[test]
fn test_malformed_data_handling() {
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
    
    // Test: malformed data should be handled gracefully
    storage.data.insert("Pdoc1".to_string(), "malformed;data;without;proper;format".to_string());
    storage.data.insert("Mdoc2".to_string(), "invalid;membership;data".to_string());
    
    // Test: should not crash on malformed data
    let result1 = authorize("doc1", "user1", READ, &mut storage, &mut trace);
    assert!(result1.is_ok());
    assert_eq!(result1.unwrap(), 0);
    
    let result2 = authorize("doc2", "user1", READ, &mut storage, &mut trace);
    assert!(result2.is_ok());
    assert_eq!(result2.unwrap(), 0);
} 