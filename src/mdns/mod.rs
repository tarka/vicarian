
use std::sync::Arc;

use anyhow::Result;
use tracing_log::log::{debug, info, warn};

use crate::{
    RunContext, config::Vhost,
};


pub struct MdnsRuntime {
    context: Arc<RunContext>,
}


impl MdnsRuntime {

    pub fn new(context: Arc<RunContext>) -> Result<Self> {
        Ok(Self {
            context,
        })
    }

    pub fn run_indefinitely(&self) -> Result<()> {
        let port = self.context.config.listen.tls_port;

        for vhost in self.context.config.vhosts.iter() {
            self.advertise(vhost)?;
        }

        Ok(())
    }

    fn advertise(&self, vhost: &Vhost) -> Result<()> {

        Ok(())
    }

}


