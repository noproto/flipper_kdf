# Flipper KDF

![](https://thumb.tildacdn.com/tild3332-3839-4061-b663-363464303432/-/resize/214x/-/format/webp/noroot.png)

[![Build and Release on Tag](https://github.com/noproto/flipper_kdf/actions/workflows/dist.yml/badge.svg)](https://github.com/noproto/flipper_kdf/actions/workflows/dist.yml)

## What

This repository tracks all available community KDF (key derivation function) plugins for the Flipper Zero.

KDF plugins:

**ST25TB**
* MyKey (*since v1.0.0*)

**MIFARE Classic**
* Saflok (*since v1.0.0*)

Have you identified a KDF that is not listed here? PR's to this repository are welcome.

## How

1. Install latest official firmware
2. Download a [release build](https://github.com/noproto/flipper_kdf/releases/latest) containing a ZIP of all of the NFC app plugins
3. Use qFlipper or the mobile app to extract the plugins to your SD card (ext) at /apps_data/nfc/plugins/
4. Scan your card as you normally would using the NFC app (NFC -> Read)

Tracking official KDF plugin support: https://github.com/flipperdevices/flipperzero-firmware/issues/3197

## Builds

Available at https://github.com/noproto/flipper_kdf/releases/latest

## Disclaimer

This repository serves as a centralized collection of plugins for compatibility with the Flipper Zero device. This compilation is intended for educational and development purposes only, and we claim no originality or ownership over contributed individual plugins. This repository is provided "as is" without any warranties, and users must adhere to the respective licenses and guidelines of the original developers or manufacturers.
