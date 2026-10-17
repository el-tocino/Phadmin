# PhAdmin

A lightweight, self-hosted web application built with **Flask** and **phue** for managing and controlling **Philips Hue** smart lighting systems. It features an embedded single-page dashboard with role-based access control (RBAC), room management, live sensor telemetry, scene saving, and bridge pairing.

---

## Features

* **Bridge Management:** Discover, pair (via physical link button), and switch between multiple Philips Hue bridges.
* **Granular Lighting & Group Control:** Control individual lights, rooms, and zones with real-time brightness, color temperature, and color adjustments.
* **Scene Support:** Save custom group light states as scenes and recall or delete them instantly.
* **Sensor & Device Telemetry:** Live monitoring for motion sensors, temperature, light levels, daylight sensors, and switches (with support for temperature unit toggling between Celsius and Fahrenheit).
* **Role-Based Access Control (RBAC):** 
  * **Admins:** Full access to all bridges, sensors, schedules, system settings, and user management.
  * **Family Members:** Restricted view and control limited specifically to assigned rooms/groups.
* **Scheduled Tasks:** Create and delete basic bridge-side time-based schedules.

---

## Installation & Setup

1. **Prerequisites:** Ensure Python 3 is installed along with Flask and `phue`:
   ```bash
   pip install flask phue
   ```

2. **Run the Application:**
   ```bash
   python phadmin.py
   ```
   *(By default, the server starts on `http://127.0.0.1:8215`)*

3. **First-Time Sign-In:**
   * On the first launch, a default `admin` account with a randomly generated secure password will be printed in your terminal.
   * Sign in using these credentials, navigate to the **Bridges** tab to pair your Philips Hue Bridge, and update your account details under the **Account** tab.