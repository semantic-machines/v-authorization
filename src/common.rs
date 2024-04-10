use crate::formats::*;
use crate::{AzContext, Right};
use core::fmt;
use std::collections::HashMap;
use std::io;

pub const PERMISSION_PREFIX: &str = "P";
pub const FILTER_PREFIX: &str = "F";
pub const MEMBERSHIP_PREFIX: &str = "M";
pub static ACCESS_8_LIST: [u8; 4] = [1, 2, 4, 8];
pub static ACCESS_8_FULL_LIST: [u8; 8] = [1, 2, 4, 8, 16, 32, 64, 128];
pub static ACCESS_PREDICATE_LIST: [&str; 9] = ["", "v-s:canCreate", "v-s:canRead", "", "v-s:canUpdate", "", "", "", "v-s:canDelete"];

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
}

impl fmt::Debug for Right {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "({}, {}, {}, {})", self.id, access_to_pretty_string(self.access), self.marker, self.level)
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
    results: &mut HashMap<String, Right>,
    level: u8,
    db: &mut dyn Storage,
    ignore_exclusive: bool,
) -> io::Result<bool> {
    if level > 32 {
        return Ok(true);
    }

    match db.get(&(MEMBERSHIP_PREFIX.to_owned() + uri)) {
        Ok(Some(groups_str)) => {
            let groups_set: &mut Vec<Right> = &mut Vec::new();
            decode_rec_to_rights(&groups_str, groups_set);

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
                    Right {
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

pub(crate) fn get_filter(id: &str, db: &mut dyn Storage) -> Option<(String, u8)> {
    let mut filter_value = "".to_string();
    let mut filter_allow_access_to_other = 0;
    match db.get(&(FILTER_PREFIX.to_owned() + id)) {
        Ok(Some(data)) => {
            filter_value = data;
            if filter_value.len() < 3 {
                filter_value.clear();
            } else {
                let filters_set: &mut Vec<Right> = &mut Vec::new();
                decode_rec_to_rights(&filter_value, filters_set);

                if !filters_set.is_empty() {
                    let el = &mut filters_set[0];

                    filter_value = el.id.clone();
                    filter_allow_access_to_other = el.access;
                }
            }
            //eprintln!("Authorize:uri=[{}], filter_value=[{}]", uri, filter_value);
        },
        Err(e) => {
            eprintln!("ERR! Authorize: _authorize {:?}, err={:?}", id, e);
            return None;
        },
        _ => {},
    }
    Some((filter_value, filter_allow_access_to_other))
}
