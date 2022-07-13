fetch(`/requires-auth`, {
  credentials: "include"
}).then((response) => {
  if (response.ok) {
    response.json().then((response) => {
      document.getElementById("response").textContent = response
    })
  }
})
