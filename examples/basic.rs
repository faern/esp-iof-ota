//!
//! Heavily inspired by https://github.com/Jeija/esp32-softap-ota
//!
//! Upload app with curl:
//! ```
//! curl --progress-bar -X POST --data-binary @build/esp32-softap-ota.bin http://192.168.4.1/update
//! ```

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
    tls::X509,
    wifi::{BlockingWifi, EspWifi},
};
use esp_idf_sys::{self as _, esp, ESP_ERR_NVS_NEW_VERSION_FOUND, ESP_ERR_NVS_NO_FREE_PAGES};
use std::{
    sync::atomic::{AtomicU8, Ordering},
    thread::{self, sleep},
    time::Duration,
};

static SSID: &str = env!("WIFI_SSID");
static PASSWORD: &str = env!("WIFI_PASS");
static INDEX_HTML: &str = include_str!("index.html");

static CERTIFICATE: X509 = X509::pem_until_nul(const_str::concat_bytes!(
    include_bytes!("../certs/server_certificate.pem"),
    b"\0"
));
static PRIVATE_KEY: X509 = X509::pem_until_nul(const_str::concat_bytes!(
    include_bytes!("../certs/private_key.pem"),
    b"\0"
));

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

    let ota_handler = esp_iof_ota::OtaHandler::new(|event| {
        log::info!("OTA event: {event:?}");
    });

    server.handler("/update", Method::Post, ota_handler)?;

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
        SSID,
        PASSWORD
    );

    Ok(wifi)
}

fn setup_httpd() -> anyhow::Result<EspHttpServer> {
    let server_configuration = esp_idf_svc::http::server::Configuration {
        stack_size: STACK_SIZE,
        http_port: 80,
        https_port: 443,
        server_certificate: Some(CERTIFICATE),
        private_key: Some(PRIVATE_KEY),
        ..Default::default()
    };

    Ok(EspHttpServer::new(&server_configuration)?)
}
