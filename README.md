## Avnet PSOC&trade; Edge Secure IoT with PSA and TF-M for /IOTCONNECT with DEEPCRAFT Ready Models Support

This project leverages the PSOC&trade; Edge Security features to provide a cutting-edge protection for IoT 
edge devices while supporting DEEPCRAFT&trade; Machine Learning Ready Models. The security features
include image signing and securing the MQTT connections with in-hardware private key protection.

This project is the integration of
[PSOC&trade; Edge MCU: DEEPCRAFT&trade; Ready Model deployment](https://github.com/Infineon/mtb-example-psoc-edge-ml-deepcraft-deploy-ready-model/tree/release-v1.2.0)
with the [Avnet /IOTCONNECT ModusToolbox&trade; SDK](https://github.com/avnet-iotconnect/avnet-iotc-mtb-sdk)
that utilizes PSA and TF-M.

The project makes use of PSOC Edge PSA and TF-M implementation 
by utilizing the factory-programmed immutable Hardware Unique Key (HUK),
to derive a private key
along with PSA Internal Trusted Storage (ITS) to store a generated certificate.
The credentials are used to securely authenticate the device to /IOTCONNECT.

The project includes various DEEPCRAFT&trade; Ready Models which are chosen at compile time by 
selecting the model in [common.mk](common.mk). Currently only the Fall Detection model is supported.
Additionally, a non-AI motion senser-based board orientation algorithm is provides.

Pre-trained models that are ready for production, referred to as "Ready Models," can be found on the [DEEPCRAFT Ready Model Landing Page](https://www.imagimob.com/ready-models). These models, when deployed on a device, are intended specifically for testing purposes and come with a limited number of inferences.

This project has a four project structure: Bootloader, CM33 secure, CM33 non-secure, and CM55 projects. The bootloader launches the CM33 secure project from a fixed location in the external flash, which then configures the protection settings and launches the CM33 non-secure application. Additionally, CM33 non-secure application enables CM55 CPU and launches the CM55 application.

The M55 processor performs the DEEPCRAFT™ model heavy lifting and reports the data via IPC to the M33 processor.
The M33 Non-Secure application is a custom /IOTCONNECT application that is receiving the IPC messages, 
processing the data and sending it to /IOTCONNECT. 
This application can receive Cloud-To-Device commands as well and control one of the board LEDs or control the application flow.

The factory-provisioned immutable Hardware Unique Key (HUK)
is used to derive a private key based on the HUK
and generate a certificate that will be stored in PSA Internal Trusted Storage (ITS).
The same certificate will be retrieved and printed upon subsequent reboots.

## Requirements

- [ModusToolbox&trade;](https://www.infineon.com/modustoolbox) with MTB Tools v3.7 or later (latest version tested with v3.9)
- Board support package (BSP) minimum required version: 1.2.0 (latest version tested with 1.4.0)
- Programming language: C
- Associated parts: All [PSOC&trade; Edge MCU](https://www.infineon.com/products/microcontroller/32-bit-psoc-arm-cortex/32-bit-psoc-edge-arm) parts

## Supported toolchains (make variable 'TOOLCHAIN')

- GNU Arm&reg; Embedded Compiler v14.2.1 (`GCC_ARM`) – Default value of `TOOLCHAIN`

> **Note:**
> This code example fails to build in RELEASE mode with the GCC_ARM toolchain v14.2.1 as it does not recognize some of the Helium instructions of the CMSIS-DSP library.

## Supported kits (make variable 'TARGET')

- [PSOC&trade; Edge E84 Evaluation Kit](https://www.infineon.com/KIT_PSE84_EVAL) (`KIT_PSE84_EVAL_EPC2`) -
[Purchase Link](https://www.newark.com/infineon/kitpse84evaltobo1/eval-kit-32bit-arm-cortex-m55f/dp/49AM4460)


## Set Up The Project

Refer to the [QUICKSTART.md](QUICKSTART.md) for instructions on how to 
quickly test and evaluate your board with /IOTCONNECT with pre-built firmware.

For general instructions on how to set up, build and run this project, refer to the 
[/IOTCONNECT ModusToolbox&trade; PSOC Edge Developer Guide](DEVELOPER_GUIDE.md)
, but refer to the section below FIRST:

- To select the model, update the `MODEL_SELECTION` variable in the [common.mk](common.mk):

| Model name           | Macro                 |
|:---------------------|:----------------------|
| Board orientation    | `MOTION_SENSOR`       |
| Fall detection       | `FALLDETECTION_MODEL` |

> **Note:** Some models, while still available in the Makefile, are not currently supported.

## Running The Demo

- After a few seconds, the device will connect to /IOTCONNECT, and begin sending telemetry packets similar to the example below 
depending on the application version and the model selected (first letter in the version prefix):

```
>: {"d":[{"d":{"version":"M-1.2.0","random":41,"event_id":0,"event":"up","event_detected":false}}]}
```
- 
- The following commands can be sent to the device using the /IOTCONNECT Web UI:

    | Command                  | Argument Type     | Description                                                                                             |
    |:-------------------------|-------------------|:--------------------------------------------------------------------------------------------------------|
    | `board-user-led`         | String (on/off)   | Turn the board LED on or off (Red LED on the EVK, Green on the AI)                                      |
    | `set-reporting-interval` | Number (eg. 2000) | Set telemetry reporting interval in milliseconds.  By default, the application will report every 2000ms |

## OTA Guide

- For more details, refer to the [OTA.md](OTA.md) document.
