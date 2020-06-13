import {supported, get, create} from  "@github/webauthn-json";


window.addEventListener("load", () => {
  const registerForm = document.getElementById("registerForm");
  registerForm.addEventListener("submit", async (e) => {
    e.preventDefault();
    const response = await fetch("/register/begin");
    const params = await response.json();

    const publicKey = {
      rp: params.rp,
      challenge: params.challenge,
      pubKeyCredParams: params.pubKeyCredParams,
      user: {
        name: "john.doe",
        displayName: "John Doe",
        id: params.user.id,
      },
    };

    const credentialCreationOptions = { publicKey };

    const credential = await create(credentialCreationOptions);
    console.log(credential);

    const result = await fetch("/register/complete", {
      method: "POST",
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(credential)
    });

    console.log(await result.text());

  });
  const loginForm = document.getElementById("loginForm");
  loginForm.addEventListener("submit", async (e) => {
    e.preventDefault();
    const response = await fetch("/login/begin");
    const params = await response.json();

    const publicKey = params;
    const credentialRequestOptions = { publicKey };

    try {
    const credential = await get(credentialRequestOptions);
    } catch (e) {
      console.log("WAT")
    }
    console.log(credential);

    const result = await fetch("/login/complete", {
      method: "POST",
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(credential)
    });

    console.log(await result.text());

  });
});
