document.getElementById("logout").addEventListener("click", async () => {
  await fetch(`/logout`, {
    credentials: "include"
  })
  window.location.href = "unauthenticated.html"
})

fetch(`/requires-auth`, {
  credentials: "include"
}).then((response) => {
  if (response.ok) {
    response.json().then((accountName) => {
      document.getElementById("loggedInAccountName").textContent = accountName
    })
  } else {
    window.location.href = "unauthenticated.html"
  }
})
