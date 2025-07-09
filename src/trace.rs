use serde_json::{json, Value};
use std::collections::{HashMap, HashSet};

const READ: u8 = 1;
const WRITE: u8 = 2;
const EXECUTE: u8 = 4;
// Добавьте другие константы прав доступа по необходимости

#[derive(Debug, Clone)]
pub enum TraceNode {
    Step {
        name: String,
        details: HashMap<String, String>,
        children: Vec<TraceNode>,
        accumulated_rights: u8,
        found_group_ids: HashSet<String>,
    },
    Group {
        id: String,
        access: u8,
        marker: char,
        is_subject: bool,
    },
    Permission {
        subject: String,
        object: String,
        access: u8,
    },
    Info(String),
}

pub struct TraceInfo {
    root: Option<TraceNode>,
    current_path: Vec<usize>,
    mode: TraceMode,
    id: Option<String>,
    user_id: Option<String>,
    request_access: Option<u8>,
}

#[derive(Clone, Copy, PartialEq, Debug)]
pub enum TraceMode {
    Disabled,
    Enabled,
    Detailed,
}

impl TraceInfo {
    pub fn new(mode: TraceMode) -> Self {
        match mode {
            TraceMode::Disabled => TraceInfo {
                root: None,
                current_path: Vec::new(),
                mode,
                id: None,
                user_id: None,
                request_access: None,
            },
            _ => TraceInfo {
                root: Some(TraceNode::Step {
                    name: "authorize".to_string(),
                    details: HashMap::new(),
                    children: Vec::new(),
                    accumulated_rights: 0,
                    found_group_ids: HashSet::new(),
                }),
                current_path: Vec::new(),
                mode,
                id: None,
                user_id: None,
                request_access: None,
            },
        }
    }

    pub fn with_details(mut self, id: &str, user_id: &str, request_access: u8) -> Self {
        if self.mode != TraceMode::Disabled {
            self.id = Some(id.to_string());
            self.user_id = Some(user_id.to_string());
            self.request_access = Some(request_access);
        }
        self
    }

    pub fn start_step(&mut self, name: &str, details: HashMap<String, String>) {
        if self.mode == TraceMode::Disabled {
            return;
        }
        let (parent_rights, parent_groups) = self.get_current_state();
        let new_step = TraceNode::Step {
            name: name.to_string(),
            details,
            children: Vec::new(),
            accumulated_rights: parent_rights,
            found_group_ids: parent_groups,
        };
        self.add_node(new_step);
        let new_index = self.get_current_children_len() - 1;
        self.current_path.push(new_index);
    }

    pub fn end_step(&mut self) {
        if self.mode == TraceMode::Disabled {
            return;
        }
        if !self.current_path.is_empty() {
            let (current_rights, current_groups) = self.get_current_state();
            self.current_path.pop();
            self.update_parent_state(current_rights, current_groups);
        }
    }

    pub fn update_step_rights(&mut self, new_rights: u8) {
        if self.mode == TraceMode::Disabled {
            return;
        }
        if let Some(TraceNode::Step { accumulated_rights, .. }) = self.get_current_node_mut() {
            *accumulated_rights |= new_rights;
        }
    }

    pub fn add_found_group(&mut self, group_id: &str) {
        if self.mode == TraceMode::Disabled {
            return;
        }
        if let Some(TraceNode::Step { found_group_ids, .. }) = self.get_current_node_mut() {
            found_group_ids.insert(group_id.to_string());
        }
    }

    fn get_current_state(&self) -> (u8, HashSet<String>) {
        match self.get_current_node() {
            Some(TraceNode::Step { accumulated_rights, found_group_ids, .. }) => (*accumulated_rights, found_group_ids.clone()),
            _ => (0, HashSet::new()),
        }
    }

    fn update_parent_state(&mut self, child_rights: u8, child_groups: HashSet<String>) {
        if let Some(TraceNode::Step { accumulated_rights, found_group_ids, .. }) = self.get_current_node_mut() {
            *accumulated_rights |= child_rights;
            found_group_ids.extend(child_groups);
        }
    }

    pub fn add_group(&mut self, id: &str, access: u8, marker: char, is_subject: bool) {
        if self.mode == TraceMode::Disabled {
            return;
        }
        let group = TraceNode::Group {
            id: id.to_string(),
            access,
            marker,
            is_subject,
        };
        self.add_node(group);
        if !is_subject {
            self.add_found_group(id);
        }
    }

    pub fn add_permission(&mut self, subject: &str, object: &str, access: u8) {
        if self.mode == TraceMode::Disabled {
            return;
        }
        let permission = TraceNode::Permission {
            subject: subject.to_string(),
            object: object.to_string(),
            access,
        };
        self.add_node(permission);
        self.update_step_rights(access);
        self.add_found_group(subject);
    }

    pub fn add_info(&mut self, info: &str) {
        if self.mode == TraceMode::Disabled {
            return;
        }
        let info_node = TraceNode::Info(info.to_string());
        self.add_node(info_node);
    }

    fn add_node(&mut self, node: TraceNode) {
        if let Some(TraceNode::Step { children, .. }) = self.get_current_node_mut() {
            children.push(node);
        }
    }

    fn get_current_node(&self) -> Option<&TraceNode> {
        self.root.as_ref().and_then(|root| {
            let mut current = root;
            for &index in &self.current_path {
                if let TraceNode::Step { children, .. } = current {
                    current = children.get(index)?;
                } else {
                    return None;
                }
            }
            Some(current)
        })
    }

    fn get_current_node_mut(&mut self) -> Option<&mut TraceNode> {
        self.root.as_mut().and_then(|root| {
            let mut current = root;
            for &index in &self.current_path {
                if let TraceNode::Step { children, .. } = current {
                    current = children.get_mut(index)?;
                } else {
                    return None;
                }
            }
            Some(current)
        })
    }

    fn get_current_children_len(&self) -> usize {
        match self.get_current_node() {
            Some(TraceNode::Step { children, .. }) => children.len(),
            _ => 0,
        }
    }

    pub fn finalize(self) -> Option<String> {
        match self.mode {
            TraceMode::Disabled => None,
            _ => Some(self.to_json_string()),
        }
    }

    fn to_json_string(&self) -> String {
        let json_value = json!({
            "id": self.id,
            "user_id": self.user_id,
            "request_access": self.request_access.map(|r| self.rights_to_string(r)),
            "trace": self.root.as_ref().map(|r| self.node_to_json(r))
        });
        serde_json::to_string_pretty(&json_value).unwrap()
    }

    fn node_to_json(&self, node: &TraceNode) -> Value {
        match node {
            TraceNode::Step { name, details, children, accumulated_rights, found_group_ids } => {
                json!({
                    "type": "step",
                    "name": name,
                    "details": details,
                    "accumulated_rights": self.rights_to_string(*accumulated_rights),
                    "found_group_ids": found_group_ids,
                    "children": children.iter().map(|child| self.node_to_json(child)).collect::<Vec<_>>()
                })
            },
            TraceNode::Group { id, access, marker, is_subject } => {
                json!({
                    "type": "group",
                    "id": id,
                    "access": self.rights_to_string(*access),
                    "marker": marker.to_string(),
                    "is_subject": is_subject
                })
            },
            TraceNode::Permission { subject, object, access } => {
                json!({
                    "type": "permission",
                    "subject": subject,
                    "object": object,
                    "access": self.rights_to_string(*access)
                })
            },
            TraceNode::Info(info) => {
                json!({
                    "type": "info",
                    "message": info
                })
            }
        }
    }

    fn rights_to_string(&self, rights: u8) -> Vec<String> {
        let mut rights_str = Vec::new();
        if rights & READ != 0 { rights_str.push("Read".to_string()); }
        if rights & WRITE != 0 { rights_str.push("Write".to_string()); }
        if rights & EXECUTE != 0 { rights_str.push("Execute".to_string()); }
        // Добавьте другие права по необходимости
        if rights_str.is_empty() {
            rights_str.push("No Rights".to_string());
        }
        rights_str
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;
    
    #[test]
    fn test_trace_mode_enum() {
        assert_eq!(TraceMode::Disabled, TraceMode::Disabled);
        assert_eq!(TraceMode::Enabled, TraceMode::Enabled);
        assert_eq!(TraceMode::Detailed, TraceMode::Detailed);
        assert_ne!(TraceMode::Disabled, TraceMode::Enabled);
    }
    
    #[test]
    fn test_trace_info_new_disabled() {
        let trace = TraceInfo::new(TraceMode::Disabled);
        assert_eq!(trace.mode, TraceMode::Disabled);
        assert!(trace.root.is_none());
        assert!(trace.current_path.is_empty());
        assert!(trace.id.is_none());
        assert!(trace.user_id.is_none());
        assert!(trace.request_access.is_none());
    }
    
    #[test]
    fn test_trace_info_new_enabled() {
        let trace = TraceInfo::new(TraceMode::Enabled);
        assert_eq!(trace.mode, TraceMode::Enabled);
        assert!(trace.root.is_some());
        assert!(trace.current_path.is_empty());
        
        if let Some(TraceNode::Step { name, children, .. }) = &trace.root {
            assert_eq!(name, "authorize");
            assert!(children.is_empty());
        } else {
            panic!("Expected Step node");
        }
    }
    
    #[test]
    fn test_trace_info_new_detailed() {
        let trace = TraceInfo::new(TraceMode::Detailed);
        assert_eq!(trace.mode, TraceMode::Detailed);
        assert!(trace.root.is_some());
        assert!(trace.current_path.is_empty());
    }
    
    #[test]
    fn test_trace_info_with_details() {
        let trace = TraceInfo::new(TraceMode::Enabled)
            .with_details("object123", "user456", 7);
        
        assert_eq!(trace.id, Some("object123".to_string()));
        assert_eq!(trace.user_id, Some("user456".to_string()));
        assert_eq!(trace.request_access, Some(7));
    }
    
    #[test]
    fn test_trace_info_with_details_disabled() {
        let trace = TraceInfo::new(TraceMode::Disabled)
            .with_details("object123", "user456", 7);
        
        assert!(trace.id.is_none());
        assert!(trace.user_id.is_none());
        assert!(trace.request_access.is_none());
    }
    
    #[test]
    fn test_start_and_end_step() {
        let mut trace = TraceInfo::new(TraceMode::Enabled);
        
        let mut details = HashMap::new();
        details.insert("key1".to_string(), "value1".to_string());
        
        trace.start_step("test_step", details);
        assert_eq!(trace.current_path.len(), 1);
        assert_eq!(trace.current_path[0], 0);
        
        trace.end_step();
        assert_eq!(trace.current_path.len(), 0);
    }
    
    #[test]
    fn test_start_and_end_step_disabled() {
        let mut trace = TraceInfo::new(TraceMode::Disabled);
        
        let details = HashMap::new();
        trace.start_step("test_step", details);
        assert_eq!(trace.current_path.len(), 0);
        
        trace.end_step();
        assert_eq!(trace.current_path.len(), 0);
    }
    
    #[test]
    fn test_nested_steps() {
        let mut trace = TraceInfo::new(TraceMode::Enabled);
        
        trace.start_step("step1", HashMap::new());
        assert_eq!(trace.current_path.len(), 1);
        
        trace.start_step("step2", HashMap::new());
        assert_eq!(trace.current_path.len(), 2);
        
        trace.end_step();
        assert_eq!(trace.current_path.len(), 1);
        
        trace.end_step();
        assert_eq!(trace.current_path.len(), 0);
    }
    
    #[test]
    fn test_update_step_rights() {
        let mut trace = TraceInfo::new(TraceMode::Enabled);
        
        trace.start_step("test_step", HashMap::new());
        trace.update_step_rights(5);
        
        if let Some(TraceNode::Step { accumulated_rights, .. }) = trace.get_current_node() {
            assert_eq!(*accumulated_rights, 5);
        } else {
            panic!("Expected Step node");
        }
        
        trace.update_step_rights(3);
        
        if let Some(TraceNode::Step { accumulated_rights, .. }) = trace.get_current_node() {
            assert_eq!(*accumulated_rights, 7); // 5 | 3 = 7
        } else {
            panic!("Expected Step node");
        }
    }
    
    #[test]
    fn test_update_step_rights_disabled() {
        let mut trace = TraceInfo::new(TraceMode::Disabled);
        
        trace.update_step_rights(5);
        // Should not panic or cause errors
        assert_eq!(trace.mode, TraceMode::Disabled);
    }
    
    #[test]
    fn test_add_found_group() {
        let mut trace = TraceInfo::new(TraceMode::Enabled);
        
        trace.start_step("test_step", HashMap::new());
        trace.add_found_group("group1");
        trace.add_found_group("group2");
        
        if let Some(TraceNode::Step { found_group_ids, .. }) = trace.get_current_node() {
            assert!(found_group_ids.contains("group1"));
            assert!(found_group_ids.contains("group2"));
            assert_eq!(found_group_ids.len(), 2);
        } else {
            panic!("Expected Step node");
        }
    }
    
    #[test]
    fn test_add_found_group_disabled() {
        let mut trace = TraceInfo::new(TraceMode::Disabled);
        
        trace.add_found_group("group1");
        // Should not panic or cause errors
        assert_eq!(trace.mode, TraceMode::Disabled);
    }
    
    #[test]
    fn test_add_group_subject() {
        let mut trace = TraceInfo::new(TraceMode::Enabled);
        
        trace.start_step("test_step", HashMap::new());
        trace.add_group("group1", 7, 'X', true);
        
        if let Some(TraceNode::Step { children, .. }) = trace.get_current_node() {
            assert_eq!(children.len(), 1);
            
            if let TraceNode::Group { id, access, marker, is_subject } = &children[0] {
                assert_eq!(id, "group1");
                assert_eq!(*access, 7);
                assert_eq!(*marker, 'X');
                assert_eq!(*is_subject, true);
            } else {
                panic!("Expected Group node");
            }
        } else {
            panic!("Expected Step node");
        }
    }
    
    #[test]
    fn test_add_group_object() {
        let mut trace = TraceInfo::new(TraceMode::Enabled);
        
        trace.start_step("test_step", HashMap::new());
        trace.add_group("group1", 7, 'X', false);
        
        // Should add to found groups when is_subject is false
        if let Some(TraceNode::Step { found_group_ids, .. }) = trace.get_current_node() {
            assert!(found_group_ids.contains("group1"));
        } else {
            panic!("Expected Step node");
        }
    }
    
    #[test]
    fn test_add_group_disabled() {
        let mut trace = TraceInfo::new(TraceMode::Disabled);
        
        trace.add_group("group1", 7, 'X', false);
        // Should not panic or cause errors
        assert_eq!(trace.mode, TraceMode::Disabled);
    }
    
    #[test]
    fn test_add_permission() {
        let mut trace = TraceInfo::new(TraceMode::Enabled);
        
        trace.start_step("test_step", HashMap::new());
        trace.add_permission("subject1", "object1", 5);
        
        if let Some(TraceNode::Step { children, accumulated_rights, found_group_ids, .. }) = trace.get_current_node() {
            assert_eq!(children.len(), 1);
            assert_eq!(*accumulated_rights, 5);
            assert!(found_group_ids.contains("subject1"));
            
            if let TraceNode::Permission { subject, object, access } = &children[0] {
                assert_eq!(subject, "subject1");
                assert_eq!(object, "object1");
                assert_eq!(*access, 5);
            } else {
                panic!("Expected Permission node");
            }
        } else {
            panic!("Expected Step node");
        }
    }
    
    #[test]
    fn test_add_permission_disabled() {
        let mut trace = TraceInfo::new(TraceMode::Disabled);
        
        trace.add_permission("subject1", "object1", 5);
        // Should not panic or cause errors
        assert_eq!(trace.mode, TraceMode::Disabled);
    }
    
    #[test]
    fn test_add_info() {
        let mut trace = TraceInfo::new(TraceMode::Enabled);
        
        trace.start_step("test_step", HashMap::new());
        trace.add_info("Test information");
        
        if let Some(TraceNode::Step { children, .. }) = trace.get_current_node() {
            assert_eq!(children.len(), 1);
            
            if let TraceNode::Info(info) = &children[0] {
                assert_eq!(info, "Test information");
            } else {
                panic!("Expected Info node");
            }
        } else {
            panic!("Expected Step node");
        }
    }
    
    #[test]
    fn test_add_info_disabled() {
        let mut trace = TraceInfo::new(TraceMode::Disabled);
        
        trace.add_info("Test information");
        // Should not panic or cause errors
        assert_eq!(trace.mode, TraceMode::Disabled);
    }
    
    #[test]
    fn test_finalize_disabled() {
        let trace = TraceInfo::new(TraceMode::Disabled);
        let result = trace.finalize();
        assert!(result.is_none());
    }
    
    #[test]
    fn test_finalize_enabled() {
        let trace = TraceInfo::new(TraceMode::Enabled)
            .with_details("object123", "user456", 7);
        let result = trace.finalize();
        assert!(result.is_some());
        
        let json_str = result.unwrap();
        assert!(json_str.contains("object123"));
        assert!(json_str.contains("user456"));
        assert!(json_str.contains("authorize"));
    }
    
    #[test]
    fn test_rights_to_string() {
        let trace = TraceInfo::new(TraceMode::Enabled);
        
        // Test individual rights
        let rights = trace.rights_to_string(READ);
        assert_eq!(rights, vec!["Read"]);
        
        let rights = trace.rights_to_string(WRITE);
        assert_eq!(rights, vec!["Write"]);
        
        let rights = trace.rights_to_string(EXECUTE);
        assert_eq!(rights, vec!["Execute"]);
        
        // Test combined rights
        let rights = trace.rights_to_string(READ | WRITE);
        assert_eq!(rights, vec!["Read", "Write"]);
        
        let rights = trace.rights_to_string(READ | WRITE | EXECUTE);
        assert_eq!(rights, vec!["Read", "Write", "Execute"]);
        
        // Test no rights
        let rights = trace.rights_to_string(0);
        assert_eq!(rights, vec!["No Rights"]);
    }
    
    #[test]
    fn test_complex_trace_scenario() {
        let mut trace = TraceInfo::new(TraceMode::Detailed)
            .with_details("doc1", "user1", 15);
        
        // Start authorization step
        trace.start_step("authorize", HashMap::new());
        trace.add_group("admin_group", 15, 'X', true);
        trace.add_permission("admin_group", "doc1", 7);
        
        // Start nested step
        trace.start_step("check_hierarchy", HashMap::new());
        trace.add_group("parent_group", 7, 0 as char, false);
        trace.add_info("Checking parent permissions");
        trace.end_step();
        
        trace.end_step();
        
        let result = trace.finalize();
        assert!(result.is_some());
        
        let json_str = result.unwrap();
        assert!(json_str.contains("doc1"));
        assert!(json_str.contains("user1"));
        assert!(json_str.contains("admin_group"));
        assert!(json_str.contains("parent_group"));
        assert!(json_str.contains("check_hierarchy"));
    }
}
