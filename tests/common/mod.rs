use std::collections::HashMap;
use std::io;
use chrono::{DateTime, Utc};
use v_authorization::common::Storage;
use v_authorization::ACLRecord;



// Common access constants for tests
pub const READ: u8 = 2;
pub const UPDATE: u8 = 4;
#[allow(dead_code)]
pub const DELETE: u8 = 8;
#[allow(dead_code)]
pub const CREATE: u8 = 1;
pub const FULL_ACCESS: u8 = 15;

/// Mock Storage implementation for testing
pub struct MockStorage {
    pub data: HashMap<String, String>,
    pub error_mode: bool,
    pub filters: HashMap<String, PermissionFilter>,
}

/// Represents a permission filter for testing
#[derive(Debug, Clone)]
pub struct PermissionFilter {
    pub resource: String,
    pub filter_resource: String,
    pub allowed_rights: u8,
    pub is_deleted: bool,
}

impl MockStorage {
    pub fn new() -> Self {
        MockStorage {
            data: HashMap::new(),
            error_mode: false,
            filters: HashMap::new(),
        }
    }

    /// Add a permission filter (mirrors v-s:PermissionFilter)
    pub fn add_permission_filter(&mut self, filter_id: &str, resource: &str, filter_resource: &str, allowed_rights: u8) {
        let filter = PermissionFilter {
            resource: resource.to_string(),
            filter_resource: filter_resource.to_string(),
            allowed_rights,
            is_deleted: false,
        };
        self.filters.insert(filter_id.to_string(), filter);
    }

    /// Delete a permission filter (mirrors v-s:deleted = true)
    pub fn delete_permission_filter(&mut self, filter_id: &str) {
        if let Some(filter) = self.filters.get_mut(filter_id) {
            filter.is_deleted = true;
        }
    }

    /// Add permission with filter support (mirrors addRight with filter parameter)
    pub fn add_right_with_filter(&mut self, subject_uri: &str, object_uri: &str, rights: u8, filter_resource: Option<&str>) {
        let key = format!("P{}", object_uri);
        let mut permission_data = String::new();
        
        // Get existing data if any
        if let Some(existing) = self.data.get(&key) {
            permission_data = existing.clone();
        }
        
        // Add new permission
        if !permission_data.is_empty() {
            permission_data.push(';');
        }
        permission_data.push_str(subject_uri);
        permission_data.push(';');
        permission_data.push_str(&encode_access(rights));
        
        // Add filter information if provided
        if let Some(filter_res) = filter_resource {
            permission_data.push(';');
            permission_data.push_str("filter:");
            permission_data.push_str(filter_res);
        }
        
        self.data.insert(key, permission_data);
    }

    /// Delete a permission (mirrors v-s:deleted = true on permission)
    pub fn delete_permission(&mut self, subject_uri: &str, object_uri: &str) {
        let key = format!("P{}", object_uri);
        if let Some(existing) = self.data.get(&key) {
            let mut new_data = String::new();
            let parts: Vec<&str> = existing.split(';').collect();
            let mut i = 0;
            
            while i < parts.len() {
                if i + 1 < parts.len() {
                    let id = parts[i];
                    let access_str = parts[i + 1];
                    
                    if id != subject_uri {
                        if !new_data.is_empty() {
                            new_data.push(';');
                        }
                        new_data.push_str(id);
                        new_data.push(';');
                        new_data.push_str(access_str);
                        
                        // Check for filter data
                        if i + 2 < parts.len() && parts[i + 2].starts_with("filter:") {
                            new_data.push(';');
                            new_data.push_str(parts[i + 2]);
                            i += 3;
                        } else {
                            i += 2;
                        }
                    } else {
                        // Skip deleted permission
                        if i + 2 < parts.len() && parts[i + 2].starts_with("filter:") {
                            i += 3;
                        } else {
                            i += 2;
                        }
                    }
                } else {
                    break;
                }
            }
            
            self.data.insert(key, new_data);
        }
    }

    /// Check if resource has active filters
    pub fn has_active_filters(&self, resource: &str) -> bool {
        self.filters.values().any(|f| f.resource == resource && !f.is_deleted)
    }

    /// Get effective rights considering filters
    pub fn get_effective_rights(&self, resource: &str, user: &str) -> u8 {
        // Find active filters for this resource
        let active_filters: Vec<&PermissionFilter> = self.filters.values()
            .filter(|f| f.resource == resource && !f.is_deleted)
            .collect();
        
        if active_filters.is_empty() {
            // No filters, return normal rights
            return self.get_user_rights(resource, user);
        }
        
        // Check if user has filtered permissions (permissions with specific filter)
        let filtered_rights = self.get_filtered_rights(resource, user);
        if filtered_rights > 0 {
            return filtered_rights;
        }
        
        // Apply filter restrictions to normal permissions
        let normal_rights = self.get_user_rights(resource, user);
        
        // If there are active filters, only the rights allowed by ALL filters are granted
        let mut effective_rights = normal_rights;
        for filter in &active_filters {
            effective_rights &= filter.allowed_rights;
        }
        
        effective_rights
    }

    /// Get user rights without filter considerations
    fn get_user_rights(&self, resource: &str, user: &str) -> u8 {
        use v_authorization::authorize;
        use v_authorization::common::Trace;
        
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
        
        // Temporarily disable filters for base rights check
        let original_filters = self.filters.clone();
        let mut temp_storage = self.clone();
        temp_storage.filters.clear();
        
        match authorize(resource, user, 255, &mut temp_storage, &mut trace) {
            Ok(access) => access,
            Err(_) => 0,
        }
    }

    /// Get filtered rights (permissions with specific filter)
    fn get_filtered_rights(&self, resource: &str, user: &str) -> u8 {
        let key = format!("P{}", resource);
        if let Some(data) = self.data.get(&key) {
            let parts: Vec<&str> = data.split(';').collect();
            let mut i = 0;
            
            while i < parts.len() {
                if i + 1 < parts.len() {
                    let id = parts[i];
                    let access_str = parts[i + 1];
                    
                    if id == user {
                        // Check if this permission has a filter
                        if i + 2 < parts.len() && parts[i + 2].starts_with("filter:") {
                            if let Ok(access) = decode_access(access_str) {
                                return access;
                            }
                        }
                    }
                    
                    if i + 2 < parts.len() && parts[i + 2].starts_with("filter:") {
                        i += 3;
                    } else {
                        i += 2;
                    }
                } else {
                    break;
                }
            }
        }
        0
    }
}

impl Clone for MockStorage {
    fn clone(&self) -> Self {
        MockStorage {
            data: self.data.clone(),
            error_mode: self.error_mode,
            filters: self.filters.clone(),
        }
    }
}

impl MockStorage {
    pub fn add_membership(&mut self, resource_id: &str, groups: &[(&str, u8)]) {
        let key = format!("M{}", resource_id);
        let mut membership_data = String::new();
        
        // Get existing data if any
        if let Some(existing) = self.data.get(&key) {
            membership_data = existing.clone();
        }
        
        // Add new groups
        for (group_id, access) in groups.iter() {
            if !membership_data.is_empty() {
                membership_data.push(';');
            }
            membership_data.push_str(group_id);
            membership_data.push(';');
            
            // For now, just use the access as-is without marker processing
            membership_data.push_str(&encode_access(*access));
        }
        
        self.data.insert(key, membership_data);
    }
    
    pub fn add_permission(&mut self, resource_id: &str, permissions: &[(&str, u8)]) {
        let key = format!("P{}", resource_id);
        let mut permission_data = String::new();
        
        // Get existing data if any
        if let Some(existing) = self.data.get(&key) {
            permission_data = existing.clone();
        }
        
        // Add new permissions
        for (subject_id, access) in permissions.iter() {
            if !permission_data.is_empty() {
                permission_data.push(';');
            }
            permission_data.push_str(subject_id);
            permission_data.push(';');
            permission_data.push_str(&encode_access(*access));
        }
        
        self.data.insert(key, permission_data);
    }
    
    /// Helper function to simulate successful read test (mirrors Helpers.test_success_read)
    #[allow(dead_code)]
    pub fn test_success_read(&mut self, resource_id: &str, user_id: &str) -> bool {
        if self.has_active_filters(resource_id) {
            let effective_rights = self.get_effective_rights(resource_id, user_id);
            effective_rights & READ != 0
        } else {
            use v_authorization::authorize;
            use v_authorization::common::Trace;
            
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
            
            match authorize(resource_id, user_id, READ, self, &mut trace) {
                Ok(access) => access & READ != 0,
                Err(_) => false,
            }
        }
    }
    
    /// Helper function to simulate failed read test (mirrors Helpers.test_fail_read)
    #[allow(dead_code)]
    pub fn test_fail_read(&mut self, resource_id: &str, user_id: &str) -> bool {
        if self.has_active_filters(resource_id) {
            let effective_rights = self.get_effective_rights(resource_id, user_id);
            effective_rights & READ == 0
        } else {
            use v_authorization::authorize;
            use v_authorization::common::Trace;
            
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
            
            match authorize(resource_id, user_id, READ, self, &mut trace) {
                Ok(access) => access & READ == 0,
                Err(_) => true,
            }
        }
    }
    
    /// Helper function to simulate successful update test (mirrors Helpers.test_success_update)
    #[allow(dead_code)]
    pub fn test_success_update(&mut self, resource_id: &str, user_id: &str) -> bool {
        if self.has_active_filters(resource_id) {
            let effective_rights = self.get_effective_rights(resource_id, user_id);
            effective_rights & UPDATE != 0
        } else {
            use v_authorization::authorize;
            use v_authorization::common::Trace;
            
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
            
            match authorize(resource_id, user_id, UPDATE, self, &mut trace) {
                Ok(access) => access & UPDATE != 0,
                Err(_) => false,
            }
        }
    }
    
    /// Helper function to simulate failed update test (mirrors Helpers.test_fail_update)
    #[allow(dead_code)]
    pub fn test_fail_update(&mut self, resource_id: &str, user_id: &str) -> bool {
        if self.has_active_filters(resource_id) {
            let effective_rights = self.get_effective_rights(resource_id, user_id);
            effective_rights & UPDATE == 0
        } else {
            use v_authorization::authorize;
            use v_authorization::common::Trace;
            
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
            
            match authorize(resource_id, user_id, UPDATE, self, &mut trace) {
                Ok(access) => access & UPDATE == 0,
                Err(_) => true,
            }
        }
    }
    
    /// Helper function to check rights success (mirrors Helpers.check_rights_success)
    #[allow(dead_code)]
    pub fn check_rights_success(&mut self, resource_id: &str, user_id: &str, expected_rights: u8) -> bool {
        use v_authorization::authorize;
        use v_authorization::common::Trace;
        
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
        
        match authorize(resource_id, user_id, expected_rights, self, &mut trace) {
            Ok(access) => access & expected_rights == expected_rights,
            Err(_) => false,
        }
    }
    
    /// Helper function to check rights failure (mirrors Helpers.check_rights_fail)
    #[allow(dead_code)]
    pub fn check_rights_fail(&mut self, resource_id: &str, user_id: &str, expected_rights: u8) -> bool {
        use v_authorization::authorize;
        use v_authorization::common::Trace;
        
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
        
        match authorize(resource_id, user_id, expected_rights, self, &mut trace) {
            Ok(access) => access & expected_rights != expected_rights,
            Err(_) => true,
        }
    }
    
    /// Helper function to add rights (mirrors Helpers.addRight)
    #[allow(dead_code)]
    pub fn add_right(&mut self, subject_uri: &str, object_uri: &str, rights: u8) {
        self.add_permission(object_uri, &[(subject_uri, rights)]);
    }
    
    /// Helper function to add to group (mirrors Helpers.addToGroup)
    #[allow(dead_code)]
    pub fn add_to_group(&mut self, group_id: &str, resource_id: &str, rights: u8) {
        self.add_membership(resource_id, &[(group_id, rights)]);
    }
    
    /// Helper function to remove from group (mirrors Helpers.removeFromGroup)
    #[allow(dead_code)]
    pub fn remove_from_group(&mut self, group_id: &str, resource_id: &str) {
        let key = format!("M{}", resource_id);
        if let Some(existing) = self.data.get(&key) {
            let mut new_data = String::new();
            let parts: Vec<&str> = existing.split(';').collect();
            let mut skip_next = false;
            
            for (_i, part) in parts.iter().enumerate() {
                if skip_next {
                    skip_next = false;
                    continue;
                }
                
                if *part == group_id {
                    skip_next = true; // Skip the access part too
                    continue;
                }
                
                if !new_data.is_empty() {
                    new_data.push(';');
                }
                new_data.push_str(part);
            }
            
            if new_data.is_empty() {
                self.data.remove(&key);
            } else {
                self.data.insert(key, new_data);
            }
        }
    }
    
    /// Helper function to create test user tickets (mirrors platform get_*_ticket functions)
    #[allow(dead_code)]
    pub fn get_admin_ticket() -> &'static str {
        "karpovrt"
    }
    
    #[allow(dead_code)]
    pub fn get_user1_ticket() -> &'static str {
        "bushenevvt"
    }
    
    #[allow(dead_code)]
    pub fn get_user2_ticket() -> &'static str {
        "BychinAt"
    }
    
    /// Helper function to generate test document URIs (mirrors platform Util.genUri)
    #[allow(dead_code)]
    pub fn gen_uri(prefix: &str) -> String {
        use std::time::{SystemTime, UNIX_EPOCH};
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        format!("{}:{}", prefix, timestamp)
    }
    
    /// Helper function to create test documents (mirrors platform generate_test_document patterns)
    #[allow(dead_code)]
    pub fn create_test_document(&mut self, author: &str, uri_prefix: &str) -> String {
        let doc_uri = Self::gen_uri(uri_prefix);
        // Author has full access to their own document
        self.add_permission(&doc_uri, &[(author, FULL_ACCESS)]);
        doc_uri
    }
    
    /// Helper function to create test groups (mirrors platform group creation patterns)
    #[allow(dead_code)]
    pub fn create_test_group(&mut self, group_prefix: &str) -> String {
        Self::gen_uri(group_prefix)
    }
    
    /// Helper function to create test membership (mirrors platform generate_test_membership patterns)
    #[allow(dead_code)]
    pub fn create_test_membership(&mut self, resource_id: &str, group_id: &str, access: u8) {
        self.add_membership(resource_id, &[(group_id, access)]);
    }
    
    /// Helper function to simulate waiting for modules (mirrors platform wait_module)
    #[allow(dead_code)]
    pub fn wait_module(&self, _module_id: u8) -> bool {
        // In tests, we don't need to actually wait
        true
    }
    
    /// Helper function to simulate removing individuals (mirrors platform remove_individual)
    #[allow(dead_code)]
    pub fn remove_individual(&mut self, resource_id: &str) {
        let permission_key = format!("P{}", resource_id);
        let membership_key = format!("M{}", resource_id);
        self.data.remove(&permission_key);
        self.data.remove(&membership_key);
    }
    
    /// Add filter for testing filter functionality
    #[allow(dead_code)]
    pub fn add_filter(&mut self, resource_id: &str, filter_data: &[(&str, u8)]) {
        let key = format!("F{}", resource_id);
        let mut filter_str = String::new();
        
        for (filter_id, access) in filter_data.iter() {
            if !filter_str.is_empty() {
                filter_str.push(';');
            }
            filter_str.push_str(filter_id);
            filter_str.push(';');
            filter_str.push_str(&encode_access(*access));
        }
        
        self.data.insert(key, filter_str);
    }
    
    /// Set error mode for testing error handling
    #[allow(dead_code)]
    pub fn set_error_mode(&mut self, error_mode: bool) {
        self.error_mode = error_mode;
    }
}

impl Storage for MockStorage {
    fn get(&mut self, key: &str) -> io::Result<Option<String>> {
        if self.error_mode {
            return Err(io::Error::new(io::ErrorKind::Other, "Mock error"));
        }
        Ok(self.data.get(key).cloned())
    }
    
    fn fiber_yield(&self) {
        // No-op in tests
    }
    
    fn decode_rec_to_rights(&self, src: &str, result: &mut Vec<ACLRecord>) -> (bool, Option<DateTime<Utc>>) {
        if src.is_empty() {
            return (true, None);
        }
        
        let parts: Vec<&str> = src.split(';').collect();
        let mut i = 0;
        
        while i < parts.len() {
            if i + 1 < parts.len() {
                let id = parts[i].to_string();
                let access_str = parts[i + 1];
                
                // Simplified: just decode access without marker processing
                let access = decode_access(access_str).unwrap_or(0);
                
                let record = ACLRecord {
                    id,
                    access,
                    marker: ' ',
                    level: 0,
                    counters: std::collections::HashMap::new(),
                    is_deleted: false,
                };
                result.push(record);
                i += 2;
            } else {
                break;
            }
        }
        
        (true, None)
    }
    
    fn decode_rec_to_rightset(&self, src: &str, new_rights: &mut v_authorization::ACLRecordSet) -> (bool, Option<DateTime<Utc>>) {
        if src.is_empty() {
            return (true, None);
        }
        
        let parts: Vec<&str> = src.split(';').collect();
        let mut i = 0;
        
        while i < parts.len() {
            if i + 1 < parts.len() {
                let id = parts[i].to_string();
                let access_str = parts[i + 1];
                
                // Simplified: just decode access without marker processing
                let access = decode_access(access_str).unwrap_or(0);
                
                let record = ACLRecord {
                    id: id.clone(),
                    access,
                    marker: ' ',
                    level: 0,
                    counters: std::collections::HashMap::new(),
                    is_deleted: false,
                };
                new_rights.insert(id, record);
                i += 2;
            } else {
                break;
            }
        }
        
        (true, None)
    }
    
    fn decode_filter(&self, filter_value: String) -> (Option<ACLRecord>, Option<DateTime<Utc>>) {
        if filter_value.is_empty() {
            return (None, None);
        }
        
        let parts: Vec<&str> = filter_value.split(';').collect();
        if parts.len() >= 2 {
            let id = parts[0].to_string();
            if let Ok(access) = decode_access(parts[1]) {
                let record = ACLRecord {
                    id,
                    access,
                    marker: ' ',
                    level: 0,
                    counters: std::collections::HashMap::new(),
                    is_deleted: false,
                };
                return (Some(record), None);
            }
        }
        
        (None, None)
    }
}

/// Helper function to encode access rights as string
fn encode_access(access: u8) -> String {
    access.to_string()
}

/// Helper function to decode access rights from string
fn decode_access(access_str: &str) -> Result<u8, std::num::ParseIntError> {
    access_str.parse()
} 