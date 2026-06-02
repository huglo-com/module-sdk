export interface GrantAuthorizedParams {
  subject: string;
  holder: string;
  scope: string;
}

/** Notify opener and close popup after grant authorization (init or callback). */
export function grantAuthorizedNotifyHtml(
  params: GrantAuthorizedParams,
  message = "Authorization complete.",
): string {
  const payloadJson = escapeScriptJson(
    JSON.stringify({
      type: "huglo:grant:authorized",
      subject: params.subject,
      holder: params.holder,
      scope: params.scope,
    }),
  );
  const escapedMessage = escapeHtml(message);
  return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <title>Huglo authorization</title>
</head>
<body>
  <p>${escapedMessage}</p>
  <script>
    (function () {
      var payload = ${payloadJson};
      if (window.opener) {
        window.opener.postMessage(payload, "*");
        window.close();
      }
    })();
  </script>
</body>
</html>`;
}

/** Minimal HTML page for the grant invite callback (errors or non-notify flows). */
export function grantCallbackHtml(message: string, autoClose: boolean): string {
  const script = autoClose
    ? "<script>window.close();</script>"
    : "";
  return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <title>Huglo authorization</title>
</head>
<body>
  <p>${escapeHtml(message)}</p>
  ${script}
</body>
</html>`;
}

function escapeHtml(text: string): string {
  return text
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;");
}

function escapeScriptJson(json: string): string {
  return json
    .replaceAll("<", "\\u003c")
    .replaceAll(">", "\\u003e")
    .replaceAll("&", "\\u0026");
}
