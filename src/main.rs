//!
//! Heavily inspired by https://github.com/Jeija/esp32-softap-ota
//!
//! Upload app with curl:
//! ```
//! curl --progress-bar -X POST --data-binary @build/esp32-softap-ota.bin http://192.168.4.1/update
//! ```

use std::{thread::sleep, time::Duration};

use embedded_svc::{
    http::{Headers, Method},
    io::Write,
    wifi::{self, AccessPointConfiguration, AuthMethod},
};
use esp_idf_hal::prelude::Peripherals;
use esp_idf_svc::{
    eventloop::EspSystemEventLoop,
    http::server::EspHttpServer,
    nvs::EspDefaultNvsPartition,
    wifi::{BlockingWifi, EspWifi},
};
use esp_idf_sys::{self as _};
use esp_idf_sys::{self as _, esp, ESP_ERR_NVS_NEW_VERSION_FOUND, ESP_ERR_NVS_NO_FREE_PAGES}; // If using the `binstart` feature of `esp-idf-sys`, always keep this module imported

const SSID: &str = env!("WIFI_SSID");
const PASSWORD: &str = env!("WIFI_PASS");
static INDEX_HTML: &str = include_str!("index.html");

const STACK_SIZE: usize = 10240;

fn main() -> anyhow::Result<()> {
    esp_idf_sys::link_patches();
    esp_idf_svc::log::EspLogger::initialize_default();

    match unsafe { esp_idf_sys::nvs_flash_init() } {
        ESP_ERR_NVS_NO_FREE_PAGES | ESP_ERR_NVS_NEW_VERSION_FOUND => {
            // NVS partition was truncated and needs to be erased
            // Retry nvs_flash_init
            esp!(unsafe { esp_idf_sys::nvs_flash_erase() })?;
            esp!(unsafe { esp_idf_sys::nvs_flash_init() })?;
        }
        err => esp!(err)?,
    }

    let wifi = setup_wifi()?;
    let mut server = setup_httpd()?;

    server.fn_handler("/", Method::Get, |req| {
        req.into_ok_response()?.write(INDEX_HTML.as_bytes())?;
        Ok(())
    })?;

    server.fn_handler("/update", Method::Post, |mut req| {
        let mut remaining = req.content_len().unwrap_or(0) as usize;
        log::info!("Starting OTA update with {remaining} bytes of app binary");

        let mut buf = vec![0u8; 1024];
        let mut ota = esp_ota::OtaUpdate::begin()?;

        while remaining > 0 {
            match req.read(&mut buf) {
                Ok(len) => {
                    assert!(len > 0);
                    log::info!("Writing {len} bytes of OTA update to flash");
                    match ota.write(&buf[..len]) {
                        Ok(()) => (),
                        Err(e) => {
                            let msg = format!("Failed to write app data to flash: {e}");
                            log::error!("{msg}");
                            req.into_status_response(500)?.write_all(msg.as_bytes())?;
                            return Ok(());
                        }
                    }
                    remaining -= len;
                }
                Err(e) => {
                    let msg = format!("Failed to read app binary from request: {e}");
                    log::error!("{msg}");
                    req.into_status_response(500)?
                        .write_all(b"Failed to read request body")?;
                    return Ok(());
                }
            }
        }

        log::info!("Done writing OTA update to flash");
        let mut completed_ota = ota.finalize()?;
        completed_ota.set_as_boot_partition()?;

        let mut response = req.into_ok_response()?;
        response.write_all(b"Firmware update complete")?;
        response.flush()?;
        drop(response);

        log::info!("Rebooting into new app in 500 ms...");
        sleep(Duration::from_millis(1000));
        completed_ota.restart();
    })?;

    core::mem::forget(server);
    core::mem::forget(wifi);

    esp_ota::mark_app_valid();

    // Main task no longer needed, free up some memory
    Ok(())
}

fn setup_wifi() -> anyhow::Result<BlockingWifi<EspWifi<'static>>> {
    let peripherals = Peripherals::take().unwrap();
    let sys_loop = EspSystemEventLoop::take()?;
    let nvs = EspDefaultNvsPartition::take()?;

    let mut wifi = BlockingWifi::wrap(
        EspWifi::new(peripherals.modem, sys_loop.clone(), Some(nvs))?,
        sys_loop,
    )?;

    let wifi_configuration = wifi::Configuration::AccessPoint(AccessPointConfiguration {
        ssid: SSID.into(),
        auth_method: AuthMethod::WPA2Personal,
        password: PASSWORD.into(),
        ..Default::default()
    });
    wifi.set_configuration(&wifi_configuration)?;
    wifi.start()?;
    wifi.wait_netif_up()?;

    log::info!(
        "Created Wi-Fi with WIFI_SSID `{}` and WIFI_PASS `{}`",
        SSID, PASSWORD
    );

    Ok(wifi)
}

fn setup_httpd() -> anyhow::Result<EspHttpServer> {
    let server_configuration = esp_idf_svc::http::server::Configuration {
        stack_size: STACK_SIZE,
        ..Default::default()
    };

    Ok(EspHttpServer::new(&server_configuration)?)
}