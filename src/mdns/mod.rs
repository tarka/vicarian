
use std::sync::Arc;

use anyhow::Result;
use tracing_log::log::{debug, info, warn};
use zbus::{Connection, Proxy, zvariant::OwnedObjectPath};

use crate::{
    RunContext, config::Vhost,
};


pub struct MdnsRuntime {
    context: Arc<RunContext>,
}

const DBUS_AVAHI_SERVICE: &str = "org.freedesktop.Avahi";
const DBUS_AVAHI_SERVER: &str = "org.freedesktop.Avahi.Server";
const DBUS_AVAHI_ENTRYGROUP: &str = "org.freedesktop.Avahi.EntryGroup";

impl MdnsRuntime {

    pub fn new(context: Arc<RunContext>) -> Result<Self> {
        Ok(Self {
            context,
        })
    }

    pub async fn run_indefinitely(&self) -> Result<()> {
        let port = self.context.config.listen.tls_port;

        let connection = Connection::system().await?;

        // Store the proxies as drop will close the service.
        let mut _groups = Vec::new();

        for vhost in self.context.config.vhosts.iter() {
            let adv = self.advertise(&connection, &vhost.hostname, port).await?;
            _groups.push(adv);

            for alias in &vhost.aliases {
                let adv = self.advertise(&connection, alias, port).await?;
                _groups.push(adv);
            }
        }

        if _groups.is_empty() {
            info!("No mDNS services advertised");
        } else {
            info!("mDNS services advertised: {}", _groups.len());
        }

        let mut quit_rx = self.context.quit_rx.clone();
        let _ = quit_rx.changed().await;
        info!("mDNS runtime shutting down");

        Ok(())
    }

    async fn advertise(&self, connection: &Connection, name: &str, port: u16) -> Result<Proxy<'static>> {
        let server = Proxy::new(
            connection,
            DBUS_AVAHI_SERVICE,
            "/",
            DBUS_AVAHI_SERVER,
        ).await?;

        let group_path: OwnedObjectPath = server.call("EntryGroupNew", &()).await?;

        let group = Proxy::new(connection, DBUS_AVAHI_SERVICE, group_path, DBUS_AVAHI_ENTRYGROUP,).await?;

        // <method name="AddService">
        //   <arg name="interface" type="i" direction="in"/>
        //   <arg name="protocol" type="i" direction="in"/>
        //   <arg name="flags" type="u" direction="in"/>
        //   <arg name="name" type="s" direction="in"/>
        //   <arg name="type" type="s" direction="in"/>
        //   <arg name="domain" type="s" direction="in"/>
        //   <arg name="host" type="s" direction="in"/>
        //   <arg name="port" type="q" direction="in"/>
        //   <arg name="txt" type="aay" direction="in"/>
        // </method>

        let txt: Vec<Vec<u8>> = Vec::new();

        let _: () = group.call("AddService", &(
            avahi_sys::AVAHI_IF_UNSPEC,
            avahi_sys::AVAHI_PROTO_UNSPEC,
            0u32,  // flags
            name,
            "_https._tcp",
            "",    // domain
            name,    // host
            port,
            txt,
        )).await?;

        let _: () = group.call("Commit", &()).await?;

        debug!("Advertised mDNS service {} on port {}", name, port);

        Ok(group)
    }

}
