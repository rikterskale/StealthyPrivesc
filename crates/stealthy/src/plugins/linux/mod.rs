mod containers;
mod credentials;
mod endpoint_controls;
mod groups;
mod kernel_cve;
mod mounts;
mod nfs;
mod path_ld;
mod polkit;
mod services;
mod ssh_keys;
mod sudo;
mod suid;
mod systemd_cron;
pub mod util;
mod wildcard_cron;

use crate::core::plugin::Plugin;

pub fn plugins() -> Vec<&'static dyn Plugin> {
    vec![
        &sudo::SudoPlugin,
        &suid::SuidPlugin,
        &systemd_cron::SystemdCronPlugin,
        &containers::ContainersPlugin,
        &groups::GroupsPlugin,
        &polkit::PolkitPlugin,
        &mounts::MountsPlugin,
        &ssh_keys::SshKeysPlugin,
        &path_ld::PathLdPlugin,
        &kernel_cve::KernelCvePlugin,
        &nfs::NfsPlugin,
        &credentials::CredentialsPlugin,
        &services::ServicesPlugin,
        &wildcard_cron::WildcardCronPlugin,
        &endpoint_controls::EndpointControlsPlugin,
    ]
}
