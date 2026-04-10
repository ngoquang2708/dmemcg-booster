use crate::cgroup::CGroup;
use std::collections::HashSet;
use std::str::FromStr;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use dbus::blocking::Connection;

mod cgroup;

fn user_slice_id(cgroup: &CGroup) -> Option<String> {
    let mut parent = cgroup.parent()?;
    loop {
        let name = parent.name();
        if !name.starts_with("user-") || !name.ends_with(".slice") {
            return None;
        }
        let id = name.get(5..name.len() - 6)?;
        if u32::from_str(id).is_ok() {
            return Some(id.to_owned());
        }
        parent = parent.parent()?;
    }
}

fn try_activate_dmem_controller(cgroup: &mut CGroup, system: bool) -> Result<(), std::io::Error> {
    /* There may be system-level cgroups we need to activate higher in the hierarchy,
     * so check these out before returning.
     */
    if let Some(mut parent) = cgroup.parent() {
        propagate_dmem_activation(&mut parent, system);
    }

    /* If we're operating on a system level, don't try messing with users' cgroups. This potentially
     * messes up permissions for the cgroup files so users can't set their own limits in child
     * cgroups.
     */
    if user_slice_id(cgroup).is_some() && system {
        return Ok(());
    }

    /* Don't try enabling the dmem controller in cgroups that are a) leaf cgroups or b) don't have
     * any other controllers set. If a controller is enabled in cgroup.subtree_control, no more
     * processes may be spawned in that cgroup. Enabling a controller ourselves could confuse
     * systemd if it can't spawn new processes all of a sudden. If there are descendant cgroups, or
     * another controller is active, enabling the dmem controller is risk-free since systemd
     * wouldn't be able to spawn a new process anyway.
     */
    let can_activate_controller = !cgroup.descendants().is_empty() || {
        if let Some(controllers) = cgroup.active_controllers() {
            !controllers.is_empty()
        } else {
            false
        }
    };
    if !can_activate_controller {
        return Ok(());
    }

    let mut retry = false;
    loop {
        return if let Err(e) = cgroup.add_controller("dmem") {
            /* NotFound means the grandparent doesn't have the controller either,
             * so try enabling controllers further up the hierarchy and retry.
             * It's possible that the dmem controller is missing on cgroups we don't have
             * permission for, so only try once and then back off.
             */
            if e.kind() == std::io::ErrorKind::NotFound
                && !retry
                && let Some(mut parent) = cgroup.parent()
            {
                propagate_dmem_activation(&mut parent, system);
                retry = true;
                continue;
            }
            Err(e)
        } else {
            Ok(())
        };
    }
}

fn propagate_dmem_activation(cgroup: &mut CGroup, system: bool) {
    let has_active_dmem = {
        if let Some(controllers) = cgroup.active_controllers() {
            controllers.contains(&String::from("dmem"))
        } else {
            return;
        }
    };

    if !has_active_dmem && try_activate_dmem_controller(cgroup, system).is_err() {
        return;
    }

    let should_set_limit = {
        /* A similar thing to try_activate_dmem_controller applies here: Don't try to mess with
         * users' cgroups if we have system-level privileges.
         * However, we do have to set the cgroup limits for the immediate user cgroups (e.g.
         * user@<id>.service, which is owned by the user, but the parent user-<id>.slice is owned by
         * root), because those are still owned by root and users can't set them.
         */
        if let Some(parent) = cgroup.parent()
            && let Some(user_id) = user_slice_id(&parent)
        {
            if system {
                return;
            }
            let name = cgroup.name();
            let user_service_name = format!("user@{user_id}.service");

            /* At the user level, the only cgroups that should receive protection are app.slice
             * (where foreground apps live) and the user@<id>.service unit, which contains
             * app.slice.
             */
            name == "app.slice" || name == user_service_name
        } else {
            true
        }
    };

    if !should_set_limit {
        return;
    }

    let Some(limits) = CGroup::root().device_memory_capacity() else {
        return;
    };
    cgroup.write_device_memory_low(&limits);
}

fn activate_dmem_in_descendants(cgroup: &mut CGroup, system: bool) {
    let descendants = cgroup.descendants();
    if descendants.is_empty() {
        propagate_dmem_activation(cgroup, system);
        return;
    }
    for mut desc in descendants {
        activate_dmem_in_descendants(&mut desc, system);
    }
}

fn handle_new_unit(connection: &Connection, unit_path: String, system: bool) {
    const TIMEOUT: Duration = Duration::from_secs(1);

    let mut cgroup: Option<String> = None;

    /* All interfaces that have the ControlGroup property */
    let iface_names = [
        "org.freedesktop.systemd1.Service",
        "org.freedesktop.systemd1.Scope",
        "org.freedesktop.systemd1.Slice",
        "org.freedesktop.systemd1.Socket",
    ];
    for iface_name in iface_names {
        let get_cgroup_proxy =
            connection.with_proxy("org.freedesktop.systemd1", &unit_path, TIMEOUT);
        let res: Result<(dbus::arg::Variant<String>,), _> = get_cgroup_proxy.method_call(
            "org.freedesktop.DBus.Properties",
            "Get",
            (iface_name, "ControlGroup"),
        );
        if let Ok((candidate_cgroup,)) = res {
            cgroup = Some(candidate_cgroup.0);
            break;
        }
    }
    let Some(cgroup) = cgroup else {
        return;
    };
    let cgroup = format!("/sys/fs/cgroup/{cgroup}");
    let mut cgroup = CGroup::from_path(cgroup.into());

    propagate_dmem_activation(&mut cgroup, system);
}

fn main() {
    let system = std::env::args()
        .into_iter()
        .any(|a| a == "--use-system-bus");

    let connection = {
        if system {
            Connection::new_system().expect("Failed to connect to DBus")
        } else {
            Connection::new_session().expect("Failed to connect to DBus")
        }
    };

    let new_unit_signal =
        dbus::message::MatchRule::new_signal("org.freedesktop.systemd1.Manager", "UnitNew");
    let unit_removed_signal =
        dbus::message::MatchRule::new_signal("org.freedesktop.systemd1.Manager", "UnitRemoved");

    let unit_queue: Arc<Mutex<HashSet<String>>> = Arc::new(Mutex::new(HashSet::new()));

    let new_unit_queue = unit_queue.clone();
    connection
        .add_match(new_unit_signal, move |_: (), _, msg| {
            let (_, unit): (String, dbus::Path) = msg.read_all().unwrap();
            let mut queue = new_unit_queue
                .lock()
                .expect("Failed to retrieve unit queue!");
            queue.insert(unit.to_string());
            true
        })
        .expect("Failed to add match!");

    let removed_unit_queue = unit_queue.clone();
    connection
        .add_match(unit_removed_signal, move |_: (), _, msg| {
            let (_, unit): (String, dbus::Path) = msg.read_all().unwrap();
            let mut queue = removed_unit_queue
                .lock()
                .expect("Failed to retrieve unit queue!");
            queue.remove(&unit.to_string());
            true
        })
        .expect("Failed to add match!");

    /* Now that we're getting notified of new units, go over all existing ones and make sure cgroup
     * accounting is enabled.
     */
    activate_dmem_in_descendants(&mut CGroup::root(), system);

    loop {
        while connection.process(Duration::from_millis(1000)).unwrap() {}
        let mut queue = unit_queue.lock().expect("Failed to retrieve unit queue!");
        for unit in queue.iter() {
            handle_new_unit(&connection, unit.to_string(), system);
        }
        queue.clear();
    }
}
