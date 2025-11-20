# Project Setup

- Launch the BSP Configurator - In MTB Assistant, choose Application page -> Configure Device
  - Ensure that View->Parameters is enabled in the menus
  - Select the *Edge Protect Solution* in the list
  - At *Edge Protect Solution - Parameters", in the right-side panel, select Launch Edge Protect Configurator.
  - Select TF-M Profile **Large**
  - Click the Save button, close the window and then File->Save in the menu of the Configurator App

When launching for the frst time, the code will generate a certificate. 
Use that printed cert to register to AWS IoTCore or IoTConnect AWS trial account (use your own certificate when creating devices). 
The same certificate will be printed upon subsequent reboots.

Set your Wi-Fi credentials and MQTT credentials at [proj_cm33_ns/mqtt_client_config.h](proj_cm33_ns/mqtt_client_config.h) accordingly.
Re-building and launching the project should connect the device to the MQTT server.
