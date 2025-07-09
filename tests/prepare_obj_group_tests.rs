use std::collections::HashMap;
use std::io;
use v_authorization::common::{Storage, Trace, M_IS_EXCLUSIVE};
use v_authorization::{ACLRecord, AzContext};
use v_authorization::prepare_obj_group::prepare_obj_group;

mod common;
use common::MockStorage;

const READ: u8 = 2;
const UPDATE: u8 = 4;
const FULL_ACCESS: u8 = 15;

// Helper function to create a basic AzContext for testing
fn create_test_context<'a>(
    id: &'a str,
    user_id: &'a str,
    request_access: u8,
    walked_groups_s: &'a mut HashMap<String, (u8, char)>,
    tree_groups_s: &'a mut HashMap<String, String>,
    walked_groups_o: &'a mut HashMap<String, u8>,
    tree_groups_o: &'a mut HashMap<String, String>,
    subject_groups: &'a mut HashMap<String, ACLRecord>,
    checked_groups: &'a mut HashMap<String, u8>,
) -> AzContext<'a> {
    AzContext {
        id,
        user_id,
        request_access,
        calc_right_res: 0,
        is_need_exclusive_az: false,
        is_found_exclusive_az: false,
        walked_groups_s,
        tree_groups_s,
        walked_groups_o,
        tree_groups_o,
        subject_groups,
        checked_groups,
        filter_value: String::new(),
    }
}

// Helper function to create a basic Trace for testing
fn create_test_trace() -> (String, String, String, Trace<'static>) {
    let mut acl = String::new();
    let mut group = String::new();
    let mut info = String::new();
    
    // We need to create static references - this is a workaround for the test
    let acl_ptr = &mut acl as *mut String;
    let group_ptr = &mut group as *mut String;
    let info_ptr = &mut info as *mut String;
    
    unsafe {
        let trace = Trace {
            acl: &mut *acl_ptr,
            is_acl: false,
            group: &mut *group_ptr,
            is_group: false,
            info: &mut *info_ptr,
            is_info: false,
            str_num: 0,
        };
        (acl, group, info, trace)
    }
}

#[test]
fn test_prepare_obj_group_deep_recursion() {
    // Test case: Deep recursion prevention (level > 32)
    let mut storage = MockStorage::new();
    let mut walked_groups_s = HashMap::new();
    let mut tree_groups_s = HashMap::new();
    let mut walked_groups_o = HashMap::new();
    let mut tree_groups_o = HashMap::new();
    let mut subject_groups = HashMap::new();
    let mut checked_groups = HashMap::new();
    
    let mut azc = create_test_context(
        "test:obj1",
        "test:user1",
        READ,
        &mut walked_groups_s,
        &mut tree_groups_s,
        &mut walked_groups_o,
        &mut tree_groups_o,
        &mut subject_groups,
        &mut checked_groups,
    );
    
    let (_acl, _group, _info, mut trace) = create_test_trace();
    
    // Call with level > 32 should return Ok(false) immediately
    let result = prepare_obj_group(
        &mut azc,
        &mut trace,
        READ,
        "test:obj1",
        FULL_ACCESS,
        33, // level > 32
        &mut storage,
    );
    
    assert!(result.is_ok());
    assert_eq!(result.unwrap(), false);
}

#[test]
fn test_prepare_obj_group_no_membership_data() {
    // Test case: No membership data in database (Ok(None))
    let mut storage = MockStorage::new();
    let mut walked_groups_s = HashMap::new();
    let mut tree_groups_s = HashMap::new();
    let mut walked_groups_o = HashMap::new();
    let mut tree_groups_o = HashMap::new();
    let mut subject_groups = HashMap::new();
    let mut checked_groups = HashMap::new();
    
    let mut azc = create_test_context(
        "test:obj1",
        "test:user1",
        READ,
        &mut walked_groups_s,
        &mut tree_groups_s,
        &mut walked_groups_o,
        &mut tree_groups_o,
        &mut subject_groups,
        &mut checked_groups,
    );
    
    let (_acl, _group, _info, mut trace) = create_test_trace();
    
    // No membership data for "test:obj1" - should return Ok(false)
    // and set is_found_exclusive_az = true for level 0
    let result = prepare_obj_group(
        &mut azc,
        &mut trace,
        READ,
        "test:obj1",
        FULL_ACCESS,
        0,
        &mut storage,
    );
    
    assert!(result.is_ok());
    assert_eq!(result.unwrap(), false);
    assert!(azc.is_found_exclusive_az);
}

#[test]
fn test_prepare_obj_group_empty_groups_set() {
    // Test case: Empty groups set (groups_set_len == 0)
    let mut storage = MockStorage::new();
    
    // Add empty membership data
    storage.data.insert("Mtest:obj1".to_string(), "".to_string());
    
    let mut walked_groups_s = HashMap::new();
    let mut tree_groups_s = HashMap::new();
    let mut walked_groups_o = HashMap::new();
    let mut tree_groups_o = HashMap::new();
    let mut subject_groups = HashMap::new();
    let mut checked_groups = HashMap::new();
    
    let mut azc = create_test_context(
        "test:obj1",
        "test:user1",
        READ,
        &mut walked_groups_s,
        &mut tree_groups_s,
        &mut walked_groups_o,
        &mut tree_groups_o,
        &mut subject_groups,
        &mut checked_groups,
    );
    
    let (_acl, _group, _info, mut trace) = create_test_trace();
    
    let result = prepare_obj_group(
        &mut azc,
        &mut trace,
        READ,
        "test:obj1",
        FULL_ACCESS,
        0,
        &mut storage,
    );
    
    assert!(result.is_ok());
    assert_eq!(result.unwrap(), false);
    assert!(azc.is_found_exclusive_az);
}

#[test]
fn test_prepare_obj_group_suffix_group_detection() {
    // Test case: Detection of "_group" suffix in group names
    let mut storage = MockStorage::new();
    
    // Add membership with "_group" suffix
    storage.add_membership("test:obj1", &[("test:admin_group", READ)]);
    
    let mut walked_groups_s = HashMap::new();
    let mut tree_groups_s = HashMap::new();
    let mut walked_groups_o = HashMap::new();
    let mut tree_groups_o = HashMap::new();
    let mut subject_groups = HashMap::new();
    let mut checked_groups = HashMap::new();
    
    let mut azc = create_test_context(
        "test:obj1",
        "test:user1",
        READ,
        &mut walked_groups_s,
        &mut tree_groups_s,
        &mut walked_groups_o,
        &mut tree_groups_o,
        &mut subject_groups,
        &mut checked_groups,
    );
    
    azc.is_need_exclusive_az = true;
    
    let (_acl, _group, _info, mut trace) = create_test_trace();
    
    let result = prepare_obj_group(
        &mut azc,
        &mut trace,
        READ,
        "test:obj1",
        FULL_ACCESS,
        0,
        &mut storage,
    );
    
    assert!(result.is_ok());
    // Should not set is_found_exclusive_az = true because "_group" suffix was found
    assert!(!azc.is_found_exclusive_az);
}

#[test]
fn test_prepare_obj_group_ttl_resources_group() {
    // Test case: TTLResourcesGroup special handling
    let mut storage = MockStorage::new();
    
    // Add membership with TTLResourcesGroup
    storage.add_membership("test:obj1", &[("cfg:TTLResourcesGroup", READ)]);
    
    let mut walked_groups_s = HashMap::new();
    let mut tree_groups_s = HashMap::new();
    let mut walked_groups_o = HashMap::new();
    let mut tree_groups_o = HashMap::new();
    let mut subject_groups = HashMap::new();
    let mut checked_groups = HashMap::new();
    
    let mut azc = create_test_context(
        "test:obj1",
        "test:user1",
        READ,
        &mut walked_groups_s,
        &mut tree_groups_s,
        &mut walked_groups_o,
        &mut tree_groups_o,
        &mut subject_groups,
        &mut checked_groups,
    );
    
    azc.is_need_exclusive_az = true;
    
    let (_acl, _group, _info, mut trace) = create_test_trace();
    
    let result = prepare_obj_group(
        &mut azc,
        &mut trace,
        READ,
        "test:obj1",
        FULL_ACCESS,
        0,
        &mut storage,
    );
    
    assert!(result.is_ok());
    // TTLResourcesGroup should set is_found_exclusive_az = true
    assert!(azc.is_found_exclusive_az);
}

#[test]
fn test_prepare_obj_group_exclusive_marker_in_subject_groups() {
    // Test case: Exclusive marker detection in subject groups
    let mut storage = MockStorage::new();
    
    // Add membership with regular group
    storage.add_membership("test:obj1", &[("test:group1", READ)]);
    
    let mut walked_groups_s = HashMap::new();
    let mut tree_groups_s = HashMap::new();
    let mut walked_groups_o = HashMap::new();
    let mut tree_groups_o = HashMap::new();
    let mut subject_groups = HashMap::new();
    let mut checked_groups = HashMap::new();
    
    // Add subject group with exclusive marker
    subject_groups.insert("test:group1".to_string(), ACLRecord {
        id: "test:group1".to_string(),
        access: READ,
        marker: M_IS_EXCLUSIVE,
        is_deleted: false,
        level: 0,
        counters: HashMap::new(),
    });
    
    let mut azc = create_test_context(
        "test:obj1",
        "test:user1",
        READ,
        &mut walked_groups_s,
        &mut tree_groups_s,
        &mut walked_groups_o,
        &mut tree_groups_o,
        &mut subject_groups,
        &mut checked_groups,
    );
    
    azc.is_need_exclusive_az = true;
    
    let (_acl, _group, _info, mut trace) = create_test_trace();
    
    let result = prepare_obj_group(
        &mut azc,
        &mut trace,
        READ,
        "test:obj1",
        FULL_ACCESS,
        0,
        &mut storage,
    );
    
    assert!(result.is_ok());
    // Should set is_found_exclusive_az = true due to exclusive marker
    assert!(azc.is_found_exclusive_az);
}

#[test]
fn test_prepare_obj_group_skip_exclusive_marker_groups() {
    // Test case: Skip groups with M_IS_EXCLUSIVE marker
    let mut storage = MockStorage::new();
    
    // Create a group with exclusive marker
    let membership_data = "test:group1;2"; // group with access 2
    storage.data.insert("Mtest:obj1".to_string(), membership_data.to_string());
    
    // Override decode to return group with exclusive marker
    let mut walked_groups_s = HashMap::new();
    let mut tree_groups_s = HashMap::new();
    let mut walked_groups_o = HashMap::new();
    let mut tree_groups_o = HashMap::new();
    let mut subject_groups = HashMap::new();
    let mut checked_groups = HashMap::new();
    
    let mut azc = create_test_context(
        "test:obj1",
        "test:user1",
        READ,
        &mut walked_groups_s,
        &mut tree_groups_s,
        &mut walked_groups_o,
        &mut tree_groups_o,
        &mut subject_groups,
        &mut checked_groups,
    );
    
    let (_acl, _group, _info, mut trace) = create_test_trace();
    
    // Mock storage that returns group with exclusive marker
    struct ExclusiveStorage {
        data: HashMap<String, String>,
    }
    
    impl Storage for ExclusiveStorage {
        fn get(&mut self, key: &str) -> io::Result<Option<String>> {
            Ok(self.data.get(key).cloned())
        }
        
        fn fiber_yield(&self) {}
        
        fn decode_rec_to_rights(&self, _src: &str, result: &mut Vec<ACLRecord>) -> (bool, Option<chrono::DateTime<chrono::Utc>>) {
            result.push(ACLRecord {
                id: "test:group1".to_string(),
                access: READ,
                marker: M_IS_EXCLUSIVE,
                is_deleted: false,
                level: 0,
                counters: HashMap::new(),
            });
            (true, None)
        }
        
        fn decode_rec_to_rightset(&self, _src: &str, _new_rights: &mut v_authorization::ACLRecordSet) -> (bool, Option<chrono::DateTime<chrono::Utc>>) {
            (true, None)
        }
        
        fn decode_filter(&self, _filter_value: String) -> (Option<ACLRecord>, Option<chrono::DateTime<chrono::Utc>>) {
            (None, None)
        }
    }
    
    let mut exclusive_storage = ExclusiveStorage {
        data: HashMap::new(),
    };
    exclusive_storage.data.insert("Mtest:obj1".to_string(), "test:group1;2".to_string());
    
    let result = prepare_obj_group(
        &mut azc,
        &mut trace,
        READ,
        "test:obj1",
        FULL_ACCESS,
        0,
        &mut exclusive_storage,
    );
    
    assert!(result.is_ok());
    assert_eq!(result.unwrap(), false);
    // walked_groups_o should be empty because exclusive groups are skipped
    assert!(azc.walked_groups_o.is_empty());
}

#[test]
fn test_prepare_obj_group_already_walked_groups() {
    // Test case: Skip already walked groups with same access
    let mut storage = MockStorage::new();
    
    storage.add_membership("test:obj1", &[("test:group1", READ)]);
    
    let mut walked_groups_s = HashMap::new();
    let mut tree_groups_s = HashMap::new();
    let mut walked_groups_o = HashMap::new();
    let mut tree_groups_o = HashMap::new();
    let mut subject_groups = HashMap::new();
    let mut checked_groups = HashMap::new();
    
    // Pre-populate walked_groups_o with same access
    walked_groups_o.insert("test:group1".to_string(), READ);
    
    let mut azc = create_test_context(
        "test:obj1",
        "test:user1",
        READ,
        &mut walked_groups_s,
        &mut tree_groups_s,
        &mut walked_groups_o,
        &mut tree_groups_o,
        &mut subject_groups,
        &mut checked_groups,
    );
    
    let (_acl, _group, _info, mut trace) = create_test_trace();
    
    let result = prepare_obj_group(
        &mut azc,
        &mut trace,
        READ,
        "test:obj1",
        FULL_ACCESS,
        0,
        &mut storage,
    );
    
    assert!(result.is_ok());
    assert_eq!(result.unwrap(), false);
    // Should still have the same access level
    assert_eq!(azc.walked_groups_o.get("test:group1"), Some(&READ));
}

#[test]
fn test_prepare_obj_group_with_tracing() {
    // Test case: Behavior with tracing enabled
    let mut storage = MockStorage::new();
    
    storage.add_membership("test:obj1", &[("test:group1", READ)]);
    
    let mut walked_groups_s = HashMap::new();
    let mut tree_groups_s = HashMap::new();
    let mut walked_groups_o = HashMap::new();
    let mut tree_groups_o = HashMap::new();
    let mut subject_groups = HashMap::new();
    let mut checked_groups = HashMap::new();
    
    let mut azc = create_test_context(
        "test:obj1",
        "test:user1",
        READ,
        &mut walked_groups_s,
        &mut tree_groups_s,
        &mut walked_groups_o,
        &mut tree_groups_o,
        &mut subject_groups,
        &mut checked_groups,
    );
    
    let (_acl, _group, _info, mut trace) = create_test_trace();
    trace.is_info = true; // Enable tracing
    
    let result = prepare_obj_group(
        &mut azc,
        &mut trace,
        READ,
        "test:obj1",
        FULL_ACCESS,
        0,
        &mut storage,
    );
    
    assert!(result.is_ok());
    assert_eq!(result.unwrap(), false);
    // With tracing enabled, tree_groups_o should be populated
    assert!(azc.tree_groups_o.contains_key("test:group1"));
    assert_eq!(azc.tree_groups_o.get("test:group1"), Some(&"test:obj1".to_string()));
}

#[test]
fn test_prepare_obj_group_database_error() {
    // Test case: Database error handling
    let mut storage = MockStorage::new();
    storage.set_error_mode(true); // Enable error mode
    
    let mut walked_groups_s = HashMap::new();
    let mut tree_groups_s = HashMap::new();
    let mut walked_groups_o = HashMap::new();
    let mut tree_groups_o = HashMap::new();
    let mut subject_groups = HashMap::new();
    let mut checked_groups = HashMap::new();
    
    let mut azc = create_test_context(
        "test:obj1",
        "test:user1",
        READ,
        &mut walked_groups_s,
        &mut tree_groups_s,
        &mut walked_groups_o,
        &mut tree_groups_o,
        &mut subject_groups,
        &mut checked_groups,
    );
    
    let (_acl, _group, _info, mut trace) = create_test_trace();
    
    let result = prepare_obj_group(
        &mut azc,
        &mut trace,
        READ,
        "test:obj1",
        FULL_ACCESS,
        0,
        &mut storage,
    );
    
    assert!(result.is_err());
    assert_eq!(result.unwrap_err().kind(), io::ErrorKind::Other);
}

#[test]
fn test_prepare_obj_group_self_reference_skip() {
    // Test case: Skip when uri equals group.id
    let mut storage = MockStorage::new();
    
    // Add membership where group ID equals URI (self-reference)
    storage.add_membership("test:obj1", &[("test:obj1", READ)]);
    
    let mut walked_groups_s = HashMap::new();
    let mut tree_groups_s = HashMap::new();
    let mut walked_groups_o = HashMap::new();
    let mut tree_groups_o = HashMap::new();
    let mut subject_groups = HashMap::new();
    let mut checked_groups = HashMap::new();
    
    let mut azc = create_test_context(
        "test:obj1",
        "test:user1",
        READ,
        &mut walked_groups_s,
        &mut tree_groups_s,
        &mut walked_groups_o,
        &mut tree_groups_o,
        &mut subject_groups,
        &mut checked_groups,
    );
    
    let (_acl, _group, _info, mut trace) = create_test_trace();
    
    let result = prepare_obj_group(
        &mut azc,
        &mut trace,
        READ,
        "test:obj1",
        FULL_ACCESS,
        0,
        &mut storage,
    );
    
    assert!(result.is_ok());
    assert_eq!(result.unwrap(), false);
    // Should still record the walked group, but skip processing
    assert!(azc.walked_groups_o.contains_key("test:obj1"));
}

#[test]
fn test_prepare_obj_group_exclusive_authorization_flow() {
    // Test case: Full exclusive authorization flow
    let mut storage = MockStorage::new();
    
    // Add regular group without "_group" suffix
    storage.add_membership("test:obj1", &[("test:regulargroup", READ)]);
    
    let mut walked_groups_s = HashMap::new();
    let mut tree_groups_s = HashMap::new();
    let mut walked_groups_o = HashMap::new();
    let mut tree_groups_o = HashMap::new();
    let mut subject_groups = HashMap::new();
    let mut checked_groups = HashMap::new();
    
    let mut azc = create_test_context(
        "test:obj1",
        "test:user1",
        READ,
        &mut walked_groups_s,
        &mut tree_groups_s,
        &mut walked_groups_o,
        &mut tree_groups_o,
        &mut subject_groups,
        &mut checked_groups,
    );
    
    azc.is_need_exclusive_az = true;
    
    let (_acl, _group, _info, mut trace) = create_test_trace();
    
    let result = prepare_obj_group(
        &mut azc,
        &mut trace,
        READ,
        "test:obj1",
        FULL_ACCESS,
        0,
        &mut storage,
    );
    
    assert!(result.is_ok());
    assert_eq!(result.unwrap(), false);
    // Should set is_found_exclusive_az = true because no "_group" suffix was found
    // and this is the last group (idx == groups_set_len - 1)
    assert!(azc.is_found_exclusive_az);
}

#[test]
fn test_prepare_obj_group_access_masking() {
    // Test case: Access masking (group.access & access)
    let mut storage = MockStorage::new();
    
    storage.add_membership("test:obj1", &[("test:group1", FULL_ACCESS)]);
    
    let mut walked_groups_s = HashMap::new();
    let mut tree_groups_s = HashMap::new();
    let mut walked_groups_o = HashMap::new();
    let mut tree_groups_o = HashMap::new();
    let mut subject_groups = HashMap::new();
    let mut checked_groups = HashMap::new();
    
    let mut azc = create_test_context(
        "test:obj1",
        "test:user1",
        READ,
        &mut walked_groups_s,
        &mut tree_groups_s,
        &mut walked_groups_o,
        &mut tree_groups_o,
        &mut subject_groups,
        &mut checked_groups,
    );
    
    let (_acl, _group, _info, mut trace) = create_test_trace();
    
    let result = prepare_obj_group(
        &mut azc,
        &mut trace,
        READ,
        "test:obj1",
        UPDATE, // Restrict access to UPDATE only
        0,
        &mut storage,
    );
    
    assert!(result.is_ok());
    assert_eq!(result.unwrap(), false);
    // The group should have masked access (FULL_ACCESS & UPDATE = UPDATE)
    assert!(azc.walked_groups_o.contains_key("test:group1"));
} 