/** Minimal HTML page for the grant invite callback; optionally auto-closes the tab. */
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
