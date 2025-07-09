pub mod authorize_obj_group;
/// This module gives function to check access of user to object
pub mod common;
pub mod prepare_obj_group;
pub mod trace;
pub mod record_formats;

use crate::authorize_obj_group::authorize_obj_group;
use crate::common::*;
use crate::prepare_obj_group::prepare_obj_group;
use std::collections::HashMap;
use std::io;
use crate::trace::{TraceInfo, TraceMode};

pub struct ACLRecord {
    pub id: String,
    pub access: u8,
    pub marker: char,
    pub is_deleted: bool,
    pub level: u8,
    pub counters: HashMap<char, u16>,
}

impl ACLRecord {
    pub fn new(id: &str) -> Self {
        ACLRecord {
            id: id.to_string(),
            access: 15,
            marker: 0 as char,
            is_deleted: false,
            level: 0,
            counters: HashMap::default(),
        }
    }
    pub fn new_with_access(id: &str, access: u8) -> Self {
        ACLRecord {
            id: id.to_string(),
            access,
            marker: 0 as char,
            is_deleted: false,
            level: 0,
            counters: HashMap::default(),
        }
    }
    
    /// Add a right with reference counting
    pub fn add_right(&mut self, right: char) {
        let count = self.counters.entry(right).or_insert(0);
        *count += 1;
        
        // Update access bitmask based on the right
        match right {
            'C' => self.access |= 1,   // CanCreate
            'R' => self.access |= 2,   // CanRead
            'U' => self.access |= 4,   // CanUpdate
            'D' => self.access |= 8,   // CanDelete
            _ => {}
        }
    }
    
    /// Remove a right with reference counting
    pub fn remove_right(&mut self, right: char) -> bool {
        if let Some(count) = self.counters.get_mut(&right) {
            *count -= 1;
            if *count == 0 {
                self.counters.remove(&right);
                
                // Remove access bitmask when no more references
                match right {
                    'C' => self.access &= !1,   // Remove CanCreate
                    'R' => self.access &= !2,   // Remove CanRead
                    'U' => self.access &= !4,   // Remove CanUpdate
                    'D' => self.access &= !8,   // Remove CanDelete
                    _ => {}
                }
                return true; // Right was completely removed
            }
        }
        false // Right still has references
    }
    
    /// Check if a right is active (has at least one reference)
    pub fn has_right(&self, right: char) -> bool {
        self.counters.get(&right).map_or(false, |&count| count > 0)
    }
    
    /// Get the reference count for a right
    pub fn get_right_count(&self, right: char) -> u16 {
        self.counters.get(&right).copied().unwrap_or(0)
    }
}

pub type ACLRecordSet = HashMap<String, ACLRecord>;

pub struct AzContext<'a> {
    pub id: &'a str,
    pub user_id: &'a str,
    pub request_access: u8,
    pub calc_right_res: u8,
    pub is_need_exclusive_az: bool,
    pub is_found_exclusive_az: bool,
    pub walked_groups_s: &'a mut HashMap<String, (u8, char)>,
    pub tree_groups_s: &'a mut HashMap<String, String>,
    pub walked_groups_o: &'a mut HashMap<String, u8>,
    pub tree_groups_o: &'a mut HashMap<String, String>,
    pub subject_groups: &'a mut HashMap<String, ACLRecord>,
    pub checked_groups: &'a mut HashMap<String, u8>,
    pub filter_value: String,
}

impl<'a> Default for AzContext<'a> {
    fn default() -> Self {
        unimplemented!()
    }
}

// Функция проверки доступа к группе объектов
fn authorize_obj_groups(id: &str, request_access: u8, db: &mut dyn Storage, trace: &mut Trace, azc: &mut AzContext) -> Option<io::Result<u8>> {
    for gr in ["v-s:AllResourcesGroup", id].iter() {
        match authorize_obj_group(azc, trace, request_access, gr, 15, db) {
            Ok(res) => {
                if res && final_check(azc, trace) {
                    return Some(Ok(azc.calc_right_res));
                }
            },
            Err(e) => return Some(Err(e)),
        }
    }

    match prepare_obj_group(azc, trace, request_access, id, 15, 0, db) {
        Ok(res) => {
            if res && final_check(azc, trace) {
                return Some(Ok(azc.calc_right_res));
            }
        },

        Err(e) => return Some(Err(e)),
    }

    None
}

pub fn trace(id: &str, user_id: &str, request_access: u8, db: &mut dyn Storage) -> Result<TraceInfo, io::Error> {
    let mut trace_info = TraceInfo::new(TraceMode::Detailed);
    let mut tr = Trace {
        acl: &mut "".to_string(),
        is_acl: false,
        group: &mut "".to_string(),
        is_group: false,
        info: &mut "".to_string(),
        is_info: false,
        str_num: 0,
    };
    authorize_and_trace(id, user_id, request_access, db, &mut tr, &mut trace_info)?;
    Ok(trace_info)
}

pub fn authorize(id: &str, user_id: &str, request_access: u8, db: &mut dyn Storage, trace: &mut Trace) -> Result<u8, io::Error> {
    let mut trace_info = TraceInfo::new(TraceMode::Disabled);
    authorize_and_trace(id, user_id, request_access, db, trace, &mut trace_info)
}

fn authorize_and_trace(id: &str, user_id: &str, request_access: u8, db: &mut dyn Storage, trace: &mut Trace, _trace_info: &mut TraceInfo) -> Result<u8, io::Error> {
    let s_groups = &mut HashMap::new();

    let mut azc = AzContext {
        id,
        user_id,
        request_access,
        calc_right_res: 0,
        is_need_exclusive_az: false,
        is_found_exclusive_az: false,
        walked_groups_s: &mut HashMap::new(),
        tree_groups_s: &mut HashMap::new(),
        walked_groups_o: &mut HashMap::new(),
        tree_groups_o: &mut HashMap::new(),
        subject_groups: &mut HashMap::new(),
        checked_groups: &mut HashMap::new(),
        filter_value: String::default(),
    };

    // читаем группы subject (ticket.user_uri)
    if trace.is_info {
        print_to_trace_info(trace, format!("authorize uri={}, user={}, request_access={}\n", id, user_id, access_to_pretty_string(request_access)));
    }

    get_resource_groups(&mut azc, trace, user_id, 15, s_groups, 0, db, false)?;

    db.fiber_yield();

    azc.subject_groups = s_groups;
    azc.subject_groups.insert(user_id.to_string(), ACLRecord::new(user_id));

    let first_level_object_groups: &mut Vec<ACLRecord> = &mut Vec::new();
    first_level_object_groups.push(ACLRecord::new(id));
    match db.get(&(MEMBERSHIP_PREFIX.to_owned() + id)) {
        Ok(Some(groups_str)) => {
            db.decode_rec_to_rights(&groups_str, first_level_object_groups);
        },
        Err(_e) => {},
        _ => {},
    }

    let mut request_access_with_filter = request_access;
    let mut filter_value = String::new();

    for gr_obj in first_level_object_groups.iter() {
        if azc.filter_value.is_empty() {
            if let (Some(f), _) = get_filter(&gr_obj.id, db) {
                filter_value = f.id;

                if !filter_value.is_empty() {
                    request_access_with_filter = request_access & f.access;
                }
                break;
            }
        }
    }

    if let Some(r) = authorize_obj_groups(id, request_access_with_filter, db, trace, &mut azc) {
        return r;
    }

    azc.filter_value = filter_value;

    if !azc.filter_value.is_empty() {
        azc.checked_groups.clear();
        azc.walked_groups_o.clear();

        if let Some(r) = authorize_obj_groups(id, request_access, db, trace, &mut azc) {
            return r;
        }
    }

    if final_check(&mut azc, trace) {
        Ok(azc.calc_right_res)
    } else {
        if trace.is_acl {
            trace.acl.clear();
        }

        if trace.is_info {
            print_to_trace_info(
                trace,
                format!(
                    "result: uri={}, user={}, request={}, answer={}\n\n",
                    azc.id,
                    azc.user_id,
                    access_to_pretty_string(azc.request_access),
                    access_to_pretty_string(0)
                ),
            );
        }

        Ok(0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_acl_record_new() {
        let record = ACLRecord::new("test_user");
        assert_eq!(record.id, "test_user");
        assert_eq!(record.access, 15); // Full access by default
        assert_eq!(record.marker, 0 as char);
        assert_eq!(record.is_deleted, false);
        assert_eq!(record.level, 0);
        assert_eq!(record.counters.len(), 0);
    }
    
    #[test]
    fn test_acl_record_new_with_access() {
        let record = ACLRecord::new_with_access("test_user", 7);
        assert_eq!(record.id, "test_user");
        assert_eq!(record.access, 7);
        assert_eq!(record.marker, 0 as char);
        assert_eq!(record.is_deleted, false);
        assert_eq!(record.level, 0);
        assert_eq!(record.counters.len(), 0);
    }
    
    #[test]
    fn test_acl_record_new_with_zero_access() {
        let record = ACLRecord::new_with_access("test_user", 0);
        assert_eq!(record.id, "test_user");
        assert_eq!(record.access, 0);
    }
    
    #[test]
    fn test_acl_record_new_with_max_access() {
        let record = ACLRecord::new_with_access("test_user", 255);
        assert_eq!(record.id, "test_user");
        assert_eq!(record.access, 255);
    }
    
    #[test]
    fn test_acl_record_debug() {
        let record = ACLRecord::new("test_user");
        let debug_str = format!("{:?}", record);
        assert!(debug_str.contains("test_user"));
        assert!(debug_str.contains("C R U D"));
    }
    
    #[test]
    fn test_acl_record_with_exclusive_marker() {
        let mut record = ACLRecord::new("test_user");
        record.marker = M_IS_EXCLUSIVE;
        let debug_str = format!("{:?}", record);
        assert!(debug_str.contains("+E"));
    }
    
    #[test]
    fn test_acl_record_with_ignore_exclusive_marker() {
        let mut record = ACLRecord::new("test_user");
        record.marker = M_IGNORE_EXCLUSIVE;
        let debug_str = format!("{:?}", record);
        assert!(debug_str.contains("-E"));
    }
    
    #[test]
    fn test_acl_record_with_counters_overlapping_rights() {
        let mut record = ACLRecord::new_with_access("test_user", 0); // Start with no rights
        
        // Test adding overlapping rights
        assert_eq!(record.access, 0);
        assert_eq!(record.has_right('R'), false);
        assert_eq!(record.get_right_count('R'), 0);
        
        // Add read right first time
        record.add_right('R');
        assert_eq!(record.access, 2); // CanRead bit set
        assert_eq!(record.has_right('R'), true);
        assert_eq!(record.get_right_count('R'), 1);
        
        // Add read right second time (overlapping)
        record.add_right('R');
        assert_eq!(record.access, 2); // Still CanRead bit set
        assert_eq!(record.has_right('R'), true);
        assert_eq!(record.get_right_count('R'), 2);
        
        // Add another overlapping read right
        record.add_right('R');
        assert_eq!(record.access, 2); // Still CanRead bit set
        assert_eq!(record.has_right('R'), true);
        assert_eq!(record.get_right_count('R'), 3);
        
        // Remove one read right - should still be active
        let fully_removed = record.remove_right('R');
        assert_eq!(fully_removed, false); // Not fully removed
        assert_eq!(record.access, 2); // Still CanRead bit set
        assert_eq!(record.has_right('R'), true);
        assert_eq!(record.get_right_count('R'), 2);
        
        // Remove second read right - should still be active
        let fully_removed = record.remove_right('R');
        assert_eq!(fully_removed, false); // Not fully removed
        assert_eq!(record.access, 2); // Still CanRead bit set
        assert_eq!(record.has_right('R'), true);
        assert_eq!(record.get_right_count('R'), 1);
        
        // Remove last read right - should be fully removed
        let fully_removed = record.remove_right('R');
        assert_eq!(fully_removed, true); // Fully removed
        assert_eq!(record.access, 0); // CanRead bit cleared
        assert_eq!(record.has_right('R'), false);
        assert_eq!(record.get_right_count('R'), 0);
        
        // Test multiple different rights
        record.add_right('C'); // Create
        record.add_right('R'); // Read
        record.add_right('U'); // Update
        record.add_right('D'); // Delete
        
        assert_eq!(record.access, 15); // All rights: C(1) + R(2) + U(4) + D(8) = 15
        assert_eq!(record.has_right('C'), true);
        assert_eq!(record.has_right('R'), true);
        assert_eq!(record.has_right('U'), true);
        assert_eq!(record.has_right('D'), true);
        
        // Add overlapping rights
        record.add_right('C');
        record.add_right('R');
        
        assert_eq!(record.access, 15); // Still all rights
        assert_eq!(record.get_right_count('C'), 2);
        assert_eq!(record.get_right_count('R'), 2);
        assert_eq!(record.get_right_count('U'), 1);
        assert_eq!(record.get_right_count('D'), 1);
        
        // Remove one Create right - should still be active
        let fully_removed = record.remove_right('C');
        assert_eq!(fully_removed, false);
        assert_eq!(record.access, 15); // Still all rights
        assert_eq!(record.has_right('C'), true);
        
        // Remove last Create right - should be fully removed
        let fully_removed = record.remove_right('C');
        assert_eq!(fully_removed, true);
        assert_eq!(record.access, 14); // All except Create: R(2) + U(4) + D(8) = 14
        assert_eq!(record.has_right('C'), false);
        assert_eq!(record.has_right('R'), true);
        assert_eq!(record.has_right('U'), true);
        assert_eq!(record.has_right('D'), true);
    }
    
    #[test]
    fn test_acl_record_with_level() {
        let mut record = ACLRecord::new("test_user");
        record.level = 3;
        assert_eq!(record.level, 3);
    }
    
    #[test]
    fn test_acl_record_with_deletion() {
        let mut record = ACLRecord::new("test_user");
        record.is_deleted = true;
        assert_eq!(record.is_deleted, true);
    }
    
    #[test]
    fn test_acl_record_counters_edge_cases() {
        let mut record = ACLRecord::new_with_access("test_user", 0);
        
        // Test removing non-existent right
        let fully_removed = record.remove_right('R');
        assert_eq!(fully_removed, false);
        assert_eq!(record.access, 0);
        assert_eq!(record.has_right('R'), false);
        assert_eq!(record.get_right_count('R'), 0);
        
        // Test unknown right character
        record.add_right('X'); // Unknown right
        assert_eq!(record.access, 0); // No access bits should be set
        assert_eq!(record.has_right('X'), true); // But counter should exist
        assert_eq!(record.get_right_count('X'), 1);
        
        // Test with existing access bits
        let mut record2 = ACLRecord::new_with_access("test_user", 7); // C+R+U = 1+2+4 = 7
        assert_eq!(record2.access, 7);
        
        // Adding rights that are already set in bitmask
        record2.add_right('C');
        assert_eq!(record2.access, 7); // Should remain 7
        assert_eq!(record2.get_right_count('C'), 1);
        
        record2.add_right('R');
        assert_eq!(record2.access, 7); // Should remain 7
        assert_eq!(record2.get_right_count('R'), 1);
        
        // Test multiple additions and removals
        for _ in 0..100 {
            record.add_right('R');
        }
        assert_eq!(record.get_right_count('R'), 100);
        assert_eq!(record.access, 2); // CanRead bit set
        assert_eq!(record.has_right('R'), true);
        
        // Remove all but one
        for _ in 0..99 {
            let fully_removed = record.remove_right('R');
            assert_eq!(fully_removed, false);
            assert_eq!(record.access, 2); // Should still be set
            assert_eq!(record.has_right('R'), true);
        }
        
        assert_eq!(record.get_right_count('R'), 1);
        
        // Remove the last one
        let fully_removed = record.remove_right('R');
        assert_eq!(fully_removed, true);
        assert_eq!(record.access, 0); // Should be cleared
        assert_eq!(record.has_right('R'), false);
        assert_eq!(record.get_right_count('R'), 0);
    }
}
