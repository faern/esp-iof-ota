use anyhow::Context;
use embedded_svc::{
    http::{
        server::{Connection, Handler, HandlerResult, Request},
        Headers,
    },
    io::{Io, Write},
};
use esp_idf_sys::{self as _};
use std::cmp;
use std::sync::atomic::{AtomicU8, Ordering};

pub use esp_ota::mark_app_valid;

const READ_BUF_SIZE: usize = 1024;

#[derive(Debug, Copy, Clone, Eq, PartialEq, Hash)]
pub enum OtaEvent {
    Started,
    Aborted,
    Completed,
}

pub struct OtaHandler<F> {
    on_event: F,
    state: AtomicU8,
}

impl<F> OtaHandler<F>
where
    F: Fn(OtaEvent) + Send,
{
    pub fn new(on_event: F) -> Self {
        OtaHandler {
            on_event,
            state: AtomicU8::new(0),
        }
    }

    fn handle_request<C>(&self, req: &mut Request<&mut C>) -> anyhow::Result<()>
    where
        C: Connection,
        <C as Io>::Error: std::error::Error + Send + Sync + 'static,
    {
        let mut ota = esp_ota::OtaUpdate::begin().context("Failed to initiate OTA update")?;

        let mut remaining =
            usize::try_from(req.content_len().unwrap_or(0)).context("Too large payload")?;
        // TODO: Check partition size against `remaining` before starting
        log::info!("Starting OTA update with {remaining} bytes of app binary");

        let mut buf = vec![0u8; READ_BUF_SIZE];
        while remaining > 0 {
            let max_read = cmp::min(buf.len(), remaining);
            let len = req
                .read(&mut buf[..max_read])
                .context("Failed to read request body")?;
            log::debug!("Writing {len} bytes of OTA update to flash");
            ota.write(&buf[..len])
                .context("Failed to write app data to flash")?;
            remaining = remaining.saturating_sub(len);
        }

        log::info!("Done writing OTA update to flash. Setting as boot partition");
        let mut completed_ota = ota.finalize()?;
        completed_ota.set_as_boot_partition()?;
        Ok(())
    }
}

impl<C, F> Handler<C> for OtaHandler<F>
where
    C: Connection,
    C::Error: std::error::Error + Send + Sync + 'static,
    F: Fn(OtaEvent) + Send,
{
    fn handle(&self, connection: &mut C) -> HandlerResult {
        let mut req = Request::wrap(connection);

        if self
            .state
            .compare_exchange(0, 1, Ordering::SeqCst, Ordering::SeqCst)
            .is_err()
        {
            req.into_status_response(409)?
                .write_all(b"Update already in progress")?;
            return Ok(());
        }

        (self.on_event)(OtaEvent::Started);
        match self.handle_request(&mut req) {
            Ok(()) => {
                let mut response = req.into_ok_response()?;
                response.write_all(b"Firmware update complete\n")?;
                // Make sure to flush, since the app is likely to shortly reboot. Hopefully
                // helps deliver the response to the client correctly.
                response.flush()?;
                self.state.store(2, Ordering::SeqCst);
                (self.on_event)(OtaEvent::Completed);
            }
            Err(msg) => {
                log::error!("{msg}");
                req.into_status_response(500)?
                    .write_all(format!("{msg:?}\n").as_bytes())?;
                self.state.store(0, Ordering::SeqCst);
                (self.on_event)(OtaEvent::Aborted);
            }
        }

        Ok(())
    }
}
