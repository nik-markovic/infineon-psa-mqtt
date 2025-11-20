# Project Setup

- Launch the BSP Configuratior - In MTB Assistant, choose the Configure Device option
  - Select the Edge Protect solution
  - Click the External Tools -> Lunach Edge Protect Configurator
  - Select TF-M Profile Large
  - Click the Save button, close the window and then File->Save in the menu of the Configurator App

When launching, the code will generate a cert. Use that printed cert to register to AWS IoTCore or IoTConnect AWS trial account (use your own certificate when creating devices)

Set your [proj_cm33_ns/mqtt_client_config.h](proj_cm33_ns/mqtt_client_config.h) accordingly.
