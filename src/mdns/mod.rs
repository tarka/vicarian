
use std::sync::Arc;

use anyhow::Result;
use tracing_log::log::{debug, info, warn};

use crate::{
    RunContext,
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

    pub async fn run_indefinitely(&self) -> Result<()> {

        let mut quit_rx = self.context.quit_rx.clone();

        Ok(())
    }

}


