use crate::authorize_obj_group::authorize_obj_group;
use crate::common::{Storage, Trace, MEMBERSHIP_PREFIX, M_IS_EXCLUSIVE};
use crate::{ACLRecord, AzContext};
use std::io;

pub fn prepare_obj_group(azc: &mut AzContext, trace: &mut Trace, request_access: u8, uri: &str, access: u8, level: u8, db: &mut dyn Storage) -> io::Result<bool> {
    if level > 32 {
        return Ok(false);
    }

    db.fiber_yield();

    let mut is_contain_suffix_group = false;
    let groups_set_len;

    match db.get(&(MEMBERSHIP_PREFIX.to_owned() + uri)) {
        Ok(Some(groups_str)) => {
            let groups_set: &mut Vec<ACLRecord> = &mut Vec::new();
            db.decode_rec_to_rights(&groups_str, groups_set);

            groups_set_len = groups_set.len();

            for (idx, group) in groups_set.iter_mut().enumerate().take(groups_set_len) {
                if group.id.is_empty() {
                    eprintln!("WARN! skip, group is null, uri={}, group.id={}", uri, group.id);
                    continue;
                }

                let new_access = group.access & access;
                group.access = new_access;

                let key = group.id.clone();

                if azc.is_need_exclusive_az && !azc.is_found_exclusive_az {
                    if level == 0 {
                        if group.id.contains("_group") {
                            is_contain_suffix_group = true;
                        }

                        if idx == groups_set_len - 1 && !is_contain_suffix_group {
                            azc.is_found_exclusive_az = true;
                        }

                        if group.id.contains("cfg:TTLResourcesGroup") {
                            azc.is_found_exclusive_az = true;
                        }
                    }

                    if !azc.is_found_exclusive_az && (level == 0 || uri.contains("_group")) && azc.subject_groups.contains_key(&key) {
                        if let Some(s_val) = azc.subject_groups.get(&key) {
                            if s_val.marker == M_IS_EXCLUSIVE {
                                azc.is_found_exclusive_az = true;
                            }
                        }
                    }
                }

                if group.marker == M_IS_EXCLUSIVE {
                    continue;
                }

                let mut preur_access = 0;

                if azc.walked_groups_o.contains_key(&key) {
                    preur_access = azc.walked_groups_o[&key];
                    if (preur_access & new_access) == new_access {
                        continue;
                    }
                }

                if trace.is_info {
                    azc.walked_groups_o.insert(key.clone(), new_access | preur_access);
                    azc.tree_groups_o.insert(key.clone(), uri.to_string());
                } else {
                    azc.walked_groups_o.insert(key.clone(), new_access | preur_access);
                }

                if uri == group.id {
                    continue;
                }

                match authorize_obj_group(azc, trace, request_access, &group.id, group.access, db) {
                    Ok(res) => {
                        if res {
                            if !azc.is_need_exclusive_az {
                                return Ok(true);
                            }

                            if azc.is_need_exclusive_az && azc.is_found_exclusive_az {
                                return Ok(true);
                            }
                        }
                    },
                    Err(e) => {
                        return Err(e);
                    },
                }

                prepare_obj_group(azc, trace, request_access, &group.id, new_access, level + 1, db)?;
            }

            if groups_set_len == 0 {
                azc.is_found_exclusive_az = true;
            }

            Ok(false)
        },
        Err(e) => {
            eprintln!("ERR! Authorize: prepare_obj_group {:?}", uri);
            Err(e)
        },
        Ok(None) => {
            if level == 0 {
                azc.is_found_exclusive_az = true;
            }
            Ok(false)
        },
    }
}
