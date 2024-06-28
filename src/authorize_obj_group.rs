use crate::common::{
    access_to_pretty_string, get_path, print_to_trace_acl, print_to_trace_group, print_to_trace_info, Storage, Trace, ACCESS_8_LIST, ACCESS_PREDICATE_LIST,
    PERMISSION_PREFIX,
};
use crate::{ACLRecord, AzContext};
use std::io;

pub(crate) fn authorize_obj_group(
    azc: &mut AzContext,
    trace: &mut Trace,
    request_access: u8,
    object_group_id: &str,
    object_group_access: u8,
    db: &mut dyn Storage,
) -> io::Result<bool> {
    // Инициализация флага авторизации и переменной для рассчитываемых прав
    let mut is_authorized = false;
    let mut calc_bits;

    // Проверяем, необходимо ли дальнейшее рассмотрение доступа
    if !trace.is_info && !trace.is_group && !trace.is_acl {
        // Расчет оставшихся прав на доступ для проверки
        let left_to_check = (azc.calc_right_res ^ request_access) & request_access;

        // Если оставшиеся права полностью покрыты текущим доступом группы, пропускаем ее
        if left_to_check & object_group_access == 0 {
            return Ok(is_authorized);
        }

        // Если группа уже проверена на данный вид доступа, пропускаем
        if let Some(v) = azc.checked_groups.get(object_group_id) {
            if *v == object_group_access {
                return Ok(is_authorized);
            }
        }

        // Добавляем группу в проверенные
        azc.checked_groups.insert(object_group_id.to_string(), object_group_access);
    }

    db.fiber_yield();

    // Вывод информации о группе, если включена соответствующая трассировка
    if trace.is_group {
        print_to_trace_group(trace, format!("{}\n", object_group_id));
    }

    // Формирование ключа для получения данных ACL
    let acl_key = if !azc.filter_value.is_empty() {
        PERMISSION_PREFIX.to_owned() + &azc.filter_value + object_group_id
    } else {
        PERMISSION_PREFIX.to_owned() + object_group_id
    };

    // Попытка получения данных об ACL из базы данных
    match db.get(&acl_key) {
        Ok(Some(str)) => {
            let permissions: &mut Vec<ACLRecord> = &mut Vec::new();

            // Декодирование прав доступа из полученной строки
            db.decode_rec_to_rights(&str, permissions);

            // Перебор полученных прав доступа
            for permission in permissions {
                // Поиск субъекта среди известных прав доступа
                let subj_id = &permission.id;
                if let Some(subj_gr) = azc.subject_groups.get(subj_id) {
                    // Сравнение доступа объекта и субъекта с учетом ограничений
                    let obj_restriction_access = object_group_access;
                    let subj_restriction_access = subj_gr.access;

                    // Расчет реального доступа на основе данных правила
                    let permission_access = if permission.access > 15 {
                        (((permission.access & 0xF0) >> 4) ^ 0x0F) & permission.access
                    } else {
                        permission.access
                    };

                    // Перебор стандартного набора прав доступа
                    for i_access in ACCESS_8_LIST.iter() {
                        let access = *i_access;
                        // Проверка соответствия запрашиваемого и предоставляемого доступов
                        if (request_access & access & obj_restriction_access & subj_restriction_access) != 0 {
                            calc_bits = access & permission_access;

                            // Если после всех проверок доступ подтвержден, обновляем результат
                            if calc_bits > 0 {
                                let prev_res = azc.calc_right_res;

                                azc.calc_right_res |= calc_bits;

                                // Если достигнут полный запрашиваемый доступ, завершаем проверку
                                if (azc.calc_right_res & request_access) == request_access {
                                    if trace.is_info {
                                    } else if !trace.is_group && !trace.is_acl {
                                        is_authorized = true;
                                        return Ok(is_authorized);
                                    }
                                }

                                // Регистрация информации о найденных правах в трассировку
                                if trace.is_info && prev_res != azc.calc_right_res {
                                    // Дополнительная информация о фильтрации
                                    let f_log_str = if !azc.filter_value.is_empty() {
                                        ", with filter ".to_owned() + &azc.filter_value
                                    } else {
                                        "".to_owned()
                                    };

                                    print_to_trace_info(
                                        trace,
                                        format!(
                                            "found permission S:[{}], O:[{}], access={} {}\n",
                                            &subj_id,
                                            &object_group_id,
                                            access_to_pretty_string(permission_access),
                                            f_log_str
                                        ),
                                    );

                                    print_to_trace_info(
                                        trace,
                                        format!(
                                            "access: request={}, calc={}, total={}\n",
                                            access_to_pretty_string(request_access),
                                            access_to_pretty_string(calc_bits),
                                            access_to_pretty_string(azc.calc_right_res)
                                        ),
                                    );

                                    // Вывод информации о пути доступа
                                    print_to_trace_info(trace, "O-PATH".to_owned() + &get_path(azc.tree_groups_o, object_group_id.to_string()) + "\n");
                                    print_to_trace_info(trace, "S-PATH".to_owned() + &get_path(azc.tree_groups_s, subj_id.to_string()) + "\n");
                                }

                                // Регистрация информации о правах доступа в трассировку ACL
                                if trace.is_acl {
                                    print_to_trace_acl(trace, format!("{};{};{}\n", object_group_id, subj_id, ACCESS_PREDICATE_LIST[*i_access as usize]));
                                }
                            }
                        }
                    }
                }
            }
        },
        Err(e) => {
            eprintln!("ERR! Authorize: authorize_obj_group:main, object_group_id={:?}", object_group_id);
            return Err(e);
        },
        _ => {},
    }

    if (azc.calc_right_res & request_access) == request_access {
        if !trace.is_info && !trace.is_group && !trace.is_acl {
            is_authorized = true;
            return Ok(is_authorized);
        }
    }

    Ok(false)
}
