/**
 * Application parameters and configuration.
 *
 * @typedef {Object} TeraBoxAppParams
 * @property {string} whost - Web host URL: 'https://jp.[TERABOX_DOMAIN]'.
 * @property {string} uhost - Upload host URL: 'https://c-jp.[TERABOX_DOMAIN]'.
 * @property {string} lang - Language code setting, default - en (English).
 * @property {TeraBoxAppParamsApp} app - Application settings.
 * @property {string} ver_android - Android version.
 * @property {string} ua - User agent string: 'terabox;[pc_app_version];PC;PC-Windows;[winver];WindowsTeraBox'.
 * @property {string} cookie - Cookie string.
 * @property {Object} auth - Authentication data (unused).
 * @property {number} account_id - Account ID.
 * @property {string} account_name - Account name.
 * @property {boolean} is_vip - VIP status flag.
 * @property {number} vip_type - VIP type:
 *     <br>0: Regular user
 *     <br>1: Regular premium
 *     <br>2: Super premium
 * @property {number} space_used - Used space in bytes.
 * @property {number} space_total - Total space in bytes.
 * @property {number} space_available - Available space in bytes.
 * @property {string} cursor - Cursor for pagination.
 * @see {@link module:api~TeraBoxApp}
 */

/**
 * Application settings.
 *
 * @typedef {Object} TeraBoxAppParamsApp
 * @property {number} app_id=250528 - Application ID.
 * @property {number} web=1 - Web flag.
 * @property {string} channel=dubox - Channel identifier.
 * @property {number} clienttype=0 - Client type.
 * @see {@link TeraBoxAppParams}
 */

/**
 * @typedef {Object} CheckLoginResponse
 * @property {number} errno - Error code:
 *  <br><code> 0</code>: OK
 *  <br><code>-6</code>: Bad auth cookie
 * @property {string} newno - Unknown (always empty).
 * @property {number} request_id - Request ID.
 * @property {string} show_msg - Server message (in most cases empty).
 * @property {number} [uk] - User ID (only if errno = 0).
 * @see {@link module:api~TeraBoxApp#checkLogin}
 */
