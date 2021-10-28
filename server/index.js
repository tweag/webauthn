import {supported, get, create} from  "@github/webauthn-json";

const SERVER = self.location.origin;
var userHandle = null;
window.addEventListener("load", () => {
  const registerForm = document.getElementById("registerForm");
  registerForm.addEventListener("submit", async (e) => {
    e.preventDefault();
    const userHandle = document.getElementById("userHandle");
    const userName = document.getElementById("userName").value;
    const displayName = document.getElementById("displayName").value;
    const response = await fetch(`${SERVER}/register/begin`, {
      method: "POST",
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        userName: userName,
        displayName: displayName,
      }),
      credentials: "include"
    });
    const params = await response.json();

    userHandle.value = params.user.id;

    const publicKey = params;

    const credentialCreationOptions = { publicKey };

    const credential = await create(credentialCreationOptions);
    console.log("credential", credential);

    const result = await fetch(`${SERVER}/register/complete`, {
      credentials: "include",
      method: "POST",
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(credential),
    });

  });
  const loginForm = document.getElementById("loginForm");
  loginForm.addEventListener("submit", async (e) => {
    e.preventDefault();
    const userHandle = document.getElementById("userHandle").value;
    const response = await fetch(`${SERVER}/login/begin`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(userHandle),
      credentials: "include"
    });
    const params = await response.json();

    const publicKey = params;
    const credentialRequestOptions = { publicKey };
    const credential = await get(credentialRequestOptions);

    const result = await fetch(`${SERVER}/login/complete`, {
      method: "POST",
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(credential),
      credentials: "include"
    });

    console.log(await result.text());

  });

  const testAuthForm = document.getElementById("testAuthForm");
  testAuthForm.addEventListener("submit", async (e) => {
    e.preventDefault();
    const userHandle = document.getElementById("userHandle").value;
    const response = await fetch(`${SERVER}/requires-auth`, {
      credentials: "include"
    });
    alert(await response.text());
  });
});
