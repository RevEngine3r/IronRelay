/**
 * IronRelay — Google Apps Script stateless relay
 *
 * Setup:
 *  1. Open Project Settings → Script Properties
 *  2. Add:
 *       CF_WORKER_URL  =  https://ironrelay.<your-subdomain>.workers.dev/tunnel
 *       RELAY_TOKEN    =  (same secret configured in CF Worker env as SHARED_SECRET)
 *  3. Deploy → Web app → Execute as: Me → Who has access: Anyone
 *  4. Copy the /exec URL → use as -relay flag in the Go client
 *
 * This script does exactly one thing: forward the POST body to the CF Worker
 * and return the response body verbatim. No parsing, no state, no logic.
 */

var CF_WORKER_URL = PropertiesService.getScriptProperties().getProperty('CF_WORKER_URL');
var RELAY_TOKEN   = PropertiesService.getScriptProperties().getProperty('RELAY_TOKEN');

function doPost(e) {
  var body = e.postData.contents;

  var options = {
    method: 'post',
    payload: body,
    contentType: 'application/octet-stream',
    // Header name matches what the CF Worker checks: X-Relay-Auth
    headers: { 'X-Relay-Auth': RELAY_TOKEN },
    muteHttpExceptions: true,
  };

  var resp = UrlFetchApp.fetch(CF_WORKER_URL, options);
  var status = resp.getResponseCode();

  if (status === 204) {
    return ContentService
      .createTextOutput('')
      .setMimeType(ContentService.MimeType.TEXT);
  }

  // Return the raw binary response as-is.
  // ContentService only supports text, so we base64-encode the bytes here
  // and the Go client decodes them. Both sides agree on this encoding.
  var bytes = resp.getContent(); // int[] array of byte values
  var blob  = Utilities.newBlob(bytes);
  var b64   = Utilities.base64Encode(blob.getBytes());

  return ContentService
    .createTextOutput(b64)
    .setMimeType(ContentService.MimeType.TEXT);
}

// doGet is used for health checks and quota monitoring.
function doGet(e) {
  return ContentService
    .createTextOutput(JSON.stringify({ ok: true, relay: 'ironrelay-gs' }))
    .setMimeType(ContentService.MimeType.JSON);
}
