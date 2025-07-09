use crate::{ACLRecord, ACLRecordSet, AzContext};
use chrono::DateTime;
use chrono::Utc;
use core::fmt;
use std::collections::HashMap;
use std::io;

pub const PERMISSION_PREFIX: &str = "P";
pub const FILTER_PREFIX: &str = "F";
pub const MEMBERSHIP_PREFIX: &str = "M";
pub static ACCESS_8_LIST: [u8; 4] = [1, 2, 4, 8];
pub static ACCESS_8_FULL_LIST: [u8; 8] = [1, 2, 4, 8, 16, 32, 64, 128];
pub static ACCESS_PREDICATE_LIST: [&str; 9] = ["", "v-s:canCreate", "v-s:canRead", "", "v-s:canUpdate", "", "", "", "v-s:canDelete"];

pub const M_IS_EXCLUSIVE: char = 'X';
pub const M_IGNORE_EXCLUSIVE: char = 'N';
pub static ACCESS_C_FULL_LIST: [char; 8] = ['M', 'R', 'U', 'P', 'm', 'r', 'u', 'p'];

/// Битовые поля для прав
#[derive(PartialEq, Eq)]
#[repr(u8)]
pub enum Access {
    /// Создание
    CanCreate = 1u8,

    /// Чтение
    CanRead = 2u8,

    /// Изменеие
    CanUpdate = 4u8,

    /// Удаление
    CanDelete = 8u8,

    /// Запрет создания
    CantCreate = 16u8,

    /// Запрет чтения
    CantRead = 32u8,

    /// Запрет обновления
    CantUpdate = 64u8,

    /// Запрет удаления
    CantDelete = 128u8,
}

pub trait AuthorizationContext {
    fn authorize(&mut self, uri: &str, user_uri: &str, request_access: u8, _is_check_for_reload: bool) -> io::Result<u8>;
    fn authorize_and_trace(&mut self, uri: &str, user_uri: &str, request_access: u8, _is_check_for_reload: bool, trace: &mut Trace) -> io::Result<u8>;
}

pub trait Storage {
    fn get(&mut self, key: &str) -> io::Result<Option<String>>;
    fn fiber_yield(&self);
    fn decode_rec_to_rights(&self, src: &str, result: &mut Vec<ACLRecord>) -> (bool, Option<DateTime<Utc>>);
    fn decode_rec_to_rightset(&self, src: &str, new_rights: &mut ACLRecordSet) -> (bool, Option<DateTime<Utc>>);
    fn decode_filter(&self, filter_value: String) -> (Option<ACLRecord>, Option<DateTime<Utc>>);
}

impl fmt::Debug for ACLRecord {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let marker = if self.marker == M_IGNORE_EXCLUSIVE {
            "-E"
        } else if self.marker == M_IS_EXCLUSIVE {
            "+E"
        } else {
            "?"
        };

        write!(f, "({}, {}, {}, {})", self.id, access_to_pretty_string(self.access), marker, self.level)
    }
}

pub struct Trace<'a> {
    pub acl: &'a mut String,
    pub is_acl: bool,

    pub group: &'a mut String,
    pub is_group: bool,

    pub info: &'a mut String,
    pub is_info: bool,

    pub str_num: u32,
}

pub(crate) fn get_resource_groups(
    ctx: &mut AzContext,
    trace: &mut Trace,
    uri: &str,
    access: u8,
    results: &mut HashMap<String, ACLRecord>,
    level: u8,
    db: &mut dyn Storage,
    ignore_exclusive: bool,
) -> io::Result<bool> {
    if level > 32 {
        return Ok(true);
    }

    match db.get(&(MEMBERSHIP_PREFIX.to_owned() + uri)) {
        Ok(Some(groups_str)) => {
            let groups_set: &mut Vec<ACLRecord> = &mut Vec::new();
            db.decode_rec_to_rights(&groups_str, groups_set);

            for (idx, group) in groups_set.iter_mut().enumerate() {
                if group.id.is_empty() {
                    eprintln!("WARN! WARN! group is null, uri={}, idx={}", uri, idx);
                    continue;
                }

                let new_access = group.access & access;
                group.access = new_access;

                let mut preur_access = 0;
                if ctx.walked_groups_s.contains_key(&group.id) {
                    preur_access = ctx.walked_groups_s[&group.id].0;
                    if (preur_access & new_access) == new_access && group.marker == ctx.walked_groups_s[&group.id].1 {
                        continue;
                    }
                }

                ctx.walked_groups_s.insert(group.id.clone(), ((new_access | preur_access), group.marker));

                if trace.is_info {
                    ctx.tree_groups_s.insert(group.id.clone(), uri.to_string());
                }

                if uri == group.id {
                    continue;
                }

                let t_ignore_exclusive = if !ignore_exclusive && group.marker == M_IGNORE_EXCLUSIVE {
                    true
                } else {
                    ignore_exclusive
                };

                db.fiber_yield();

                get_resource_groups(ctx, trace, &group.id, 15, results, level + 1, db, t_ignore_exclusive)?;

                if !ignore_exclusive && group.marker == M_IS_EXCLUSIVE {
                    if trace.is_info {
                        print_to_trace_info(trace, format!("FOUND EXCLUSIVE RESTRICTIONS, PATH={} \n", &get_path(ctx.tree_groups_s, group.id.clone())));
                    }
                    ctx.is_need_exclusive_az = true;
                }

                let new_group_marker;

                match results.get(&group.id) {
                    Some(val) => {
                        if val.marker == 0 as char {
                            new_group_marker = group.marker;
                        } else {
                            new_group_marker = val.marker;
                        }
                    },
                    None => {
                        new_group_marker = group.marker;
                    },
                }

                results.insert(
                    group.id.clone(),
                    ACLRecord {
                        id: group.id.clone(),
                        access: group.access,
                        marker: new_group_marker,
                        is_deleted: group.is_deleted,
                        level,
                        counters: HashMap::default(),
                    },
                );
            }
        },
        Err(e) => {
            eprintln!("ERR! Authorize: get_resource_groups {:?}", uri);
            return Err(e);
        },
        Ok(None) => {
            return Ok(false);
        },
    }

    Ok(false)
}

pub(crate) fn print_to_trace_acl(trace: &mut Trace, text: String) {
    trace.acl.push_str(&text);
}

pub(crate) fn print_to_trace_group(trace: &mut Trace, text: String) {
    trace.group.push_str(&text);
}

pub(crate) fn print_to_trace_info(trace: &mut Trace, text: String) {
    trace.str_num += 1;
    trace.info.push_str(&(trace.str_num.to_string() + " " + &text));
}

pub(crate) fn get_path(mopc: &mut HashMap<String, String>, el: String) -> String {
    if mopc.contains_key(&el) {
        let parent = mopc[&el].clone();
        mopc.remove(&el);
        let prev = get_path(mopc, parent);

        prev + "->" + &el
    } else {
        "".to_owned()
    }
}

pub(crate) fn access_to_pretty_string(src: u8) -> String {
    let mut res: String = "".to_owned();

    if src & 1 == 1 {
        res.push_str("C ");
    }

    if src & 2 == 2 {
        res.push_str("R ");
    }

    if src & 4 == 4 {
        res.push_str("U ");
    }

    if src & 8 == 8 {
        res.push_str("D ");
    }

    if src & 16 == 16 {
        res.push_str("!C ");
    }

    if src & 32 == 32 {
        res.push_str("!R ");
    }

    if src & 64 == 64 {
        res.push_str("!U ");
    }

    if src & 128 == 128 {
        res.push_str("!D ");
    }

    res
}

pub(crate) fn final_check(azc: &mut AzContext, trace: &mut Trace) -> bool {
    let res = if azc.is_need_exclusive_az && azc.is_found_exclusive_az {
        true
    } else {
        !azc.is_need_exclusive_az
    };

    if trace.is_info && res {
        print_to_trace_info(
            trace,
            format!(
                "result: uri={}, user={}, request={}, answer={}\n\n",
                azc.id,
                azc.user_id,
                access_to_pretty_string(azc.request_access),
                access_to_pretty_string(azc.calc_right_res)
            ),
        );
    }

    res
}

pub(crate) fn get_filter(id: &str, db: &mut dyn Storage) -> (Option<ACLRecord>, Option<DateTime<Utc>>) {
    let filter_value = match db.get(&(FILTER_PREFIX.to_owned() + id)) {
        Ok(Some(data)) => data,
        Err(e) => {
            eprintln!("ERR! Authorize: _authorize {:?}, err={:?}", id, e);
            return (None, None);
        },
        _ => "".to_string(),
    };

    let res = db.decode_filter(filter_value);
    res
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_access_to_pretty_string() {
        // Test individual permissions
        assert_eq!(access_to_pretty_string(Access::CanCreate as u8), "C ");
        assert_eq!(access_to_pretty_string(Access::CanRead as u8), "R ");
        assert_eq!(access_to_pretty_string(Access::CanUpdate as u8), "U ");
        assert_eq!(access_to_pretty_string(Access::CanDelete as u8), "D ");
        
        // Test combined permissions
        assert_eq!(access_to_pretty_string(Access::CanRead as u8 | Access::CanUpdate as u8), "R U ");
        assert_eq!(access_to_pretty_string(15), "C R U D "); // All positive rights
        
        // Test deny permissions
        assert_eq!(access_to_pretty_string(Access::CantCreate as u8), "!C ");
        assert_eq!(access_to_pretty_string(Access::CantRead as u8), "!R ");
        assert_eq!(access_to_pretty_string(Access::CantUpdate as u8), "!U ");
        assert_eq!(access_to_pretty_string(Access::CantDelete as u8), "!D ");
        
        // Test zero access
        assert_eq!(access_to_pretty_string(0), "");
    }
    
    #[test]
    fn test_access_constants() {
        // Test that access constants are correctly defined
        assert_eq!(Access::CanCreate as u8, 1);
        assert_eq!(Access::CanRead as u8, 2);
        assert_eq!(Access::CanUpdate as u8, 4);
        assert_eq!(Access::CanDelete as u8, 8);
        assert_eq!(Access::CantCreate as u8, 16);
        assert_eq!(Access::CantRead as u8, 32);
        assert_eq!(Access::CantUpdate as u8, 64);
        assert_eq!(Access::CantDelete as u8, 128);
    }
    
    #[test]
    fn test_acl_record_creation() {
        // Test ACLRecord::new
        let record = ACLRecord::new("test_id");
        assert_eq!(record.id, "test_id");
        assert_eq!(record.access, 15); // Full access by default
        assert_eq!(record.marker, 0 as char);
        assert_eq!(record.is_deleted, false);
        assert_eq!(record.level, 0);
        
        // Test ACLRecord::new_with_access
        let record2 = ACLRecord::new_with_access("test_id2", Access::CanRead as u8);
        assert_eq!(record2.id, "test_id2");
        assert_eq!(record2.access, Access::CanRead as u8);
        assert_eq!(record2.marker, 0 as char);
        assert_eq!(record2.is_deleted, false);
        assert_eq!(record2.level, 0);
    }
    
    #[test]
    fn test_acl_record_debug() {
        // Test that ACLRecord debug output is readable
        let record = ACLRecord::new_with_access("test_user", Access::CanRead as u8 | Access::CanUpdate as u8);
        let debug_str = format!("{:?}", record);
        assert!(debug_str.contains("test_user"));
        assert!(debug_str.contains("R U"));
    }
    
    #[test]
    fn test_prefixes() {
        // Test that prefixes are correctly defined
        assert_eq!(PERMISSION_PREFIX, "P");
        assert_eq!(FILTER_PREFIX, "F");
        assert_eq!(MEMBERSHIP_PREFIX, "M");
    }
    
    #[test]
    fn test_exclusive_markers() {
        // Test exclusive marker constants
        assert_eq!(M_IS_EXCLUSIVE, 'X');
        assert_eq!(M_IGNORE_EXCLUSIVE, 'N');
    }
    
    #[test]
    fn test_get_path() {
        let mut tree = HashMap::new();
        tree.insert("child".to_string(), "parent".to_string());
        tree.insert("parent".to_string(), "grandparent".to_string());
        
        let path = get_path(&mut tree, "child".to_string());
        // Function removes elements as it traverses, so grandparent is not found
        assert_eq!(path, "->parent->child");
    }
    
    #[test]
    fn test_get_path_empty() {
        let mut tree = HashMap::new();
        let path = get_path(&mut tree, "nonexistent".to_string());
        assert_eq!(path, "");
    }
    
    #[test]
    fn test_trace_functions() {
        // Test print_to_trace_acl
        {
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
            
            print_to_trace_acl(&mut trace, "test acl".to_string());
            drop(trace); // Release mutable borrows
            assert_eq!(acl, "test acl");
        }
        
        // Test print_to_trace_group
        {
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
            
            print_to_trace_group(&mut trace, "test group".to_string());
            drop(trace); // Release mutable borrows
            assert_eq!(group, "test group");
        }
        
        // Test print_to_trace_info
        {
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
            
            print_to_trace_info(&mut trace, "test info".to_string());
            let str_num = trace.str_num;
            drop(trace); // Release mutable borrows
            assert_eq!(info, "1 test info");
            assert_eq!(str_num, 1);
        }
    }
}
