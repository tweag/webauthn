import {supported, get, create} from  "@github/webauthn-json";

document.getElementById("registerForm").addEventListener("submit", async (e) => {
  e.preventDefault();
  const accountName = document.getElementById("registerAccountName").value;
  var accountDisplayName = document.getElementById("accountDisplayName").value;
  if (accountDisplayName == "") {
    accountDisplayName = accountName
  }
  const response = await fetch(`/register/begin`, {
    method: "POST",
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      accountName: accountName,
      accountDisplayName: accountDisplayName,
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

  const response2 = await fetch(`/register/complete`, {
    credentials: "include",
    method: "POST",
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(credential),
  });
  if (! response2.ok) {
    alert(await response2.text())
    return
  }
  const jsonResponse2 = await response2.json();
  window.location.href = "authenticated.html"
})

document.getElementById("loginForm").addEventListener("submit", async (e) => {
  e.preventDefault();

  const accountName = document.getElementById("loginAccountName").value;
  const response = await fetch(`/login/begin`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(accountName),
    credentials: "include"
  });

  if (! response.ok) {
    alert(await response.text())
    return
  }
  const jsonResponse = await response.json();

  const credential = await get({
    "publicKey": jsonResponse
  });

  const response2 = await fetch(`/login/complete`, {
    method: "POST",
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(credential),
    credentials: "include"
  });

  if (! response2.ok) {
    alert(await response2.text())
    return
  }
  const jsonResponse2 = await response2.json()
  window.location.href = "authenticated.html"
})
