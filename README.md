# HA Remote Add-ons

[![Open your Home Assistant instance and open the ingress URL of an add-on.](https://my.home-assistant.io/badges/supervisor_ingress.svg)](https://my.home-assistant.io/redirect/supervisor_ingress/?addon=https%3A%2F%2Fgithub.com%2Fcharlyschulte%2Fha-remote)

## Install with one click
1. Click the button above (or open the link in a browser where you are signed into your Home Assistant instance).
2. Confirm adding the repository.
3. Install **HA Remote Connectors** from the Add-on Store.

## Install by pasting the GitHub URL
1. In Home Assistant, go to **Settings → Add-ons → Add-on Store**.
2. Open the menu (⋮) → **Repositories**.
3. Paste this URL and click **Add**:
   - https://github.com/charlyschulte/ha-remote

## Updating the add-on
- Bump the `version` in [config.yaml](config.yaml).
- Commit and push to GitHub.
- Home Assistant will show the update automatically in the Add-on Store.

## Notes
- If the GitHub URL or maintainer changes, update [repository.json](repository.json) accordingly.
