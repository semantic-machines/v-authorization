mod authorize_obj_group;
/// This module gives function to check access of user to object
pub mod common;
mod prepare_obj_group;

use crate::authorize_obj_group::authorize_obj_group;
use crate::common::*;
use crate::prepare_obj_group::prepare_obj_group;
use std::collections::HashMap;
use std::io;

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
}

pub type ACLRecordSet = HashMap<String, ACLRecord>;

pub(crate) struct AzContext<'a> {
    id: &'a str,
    user_id: &'a str,
    request_access: u8,
    calc_right_res: u8,
    is_need_exclusive_az: bool,
    is_found_exclusive_az: bool,
    walked_groups_s: &'a mut HashMap<String, (u8, char)>,
    tree_groups_s: &'a mut HashMap<String, String>,
    walked_groups_o: &'a mut HashMap<String, u8>,
    tree_groups_o: &'a mut HashMap<String, String>,
    subject_groups: &'a mut HashMap<String, ACLRecord>,
    checked_groups: &'a mut HashMap<String, u8>,
    filter_value: String,
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

pub fn authorize(id: &str, user_id: &str, request_access: u8, db: &mut dyn Storage, trace: &mut Trace) -> Result<u8, std::io::Error> {
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
