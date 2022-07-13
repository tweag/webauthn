import {supported, get, create} from  "@github/webauthn-json";

document.getElementById("registerForm").addEventListener("submit", async (e) => {
  e.preventDefault();
  if (! supported()) {
    alert("WebAuthn is not supported on this device");
    return;
  }

  const response = await fetch(`/register/begin`, {
    method: "POST",
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      accountName: "testAccountName",
      accountDisplayName: "testAccountDisplayName",
    }),
    credentials: "include"
  });

  if (! response.ok) {
    alert(await response.text())
    return
  }
  const jsonResponse = await response.json();

  const credential = await create({
    "publicKey": jsonResponse
  });

  document.getElementById("response").textContent = JSON.stringify(credential)
})
