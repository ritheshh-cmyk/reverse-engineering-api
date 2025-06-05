document.getElementById("fileForm").onsubmit = async (e) => {
  e.preventDefault();
  const form = new FormData(e.target);
  const res = await fetch("/analyze-file", { method: "POST", body: form });
  const data = await res.json();
  document.getElementById("output").textContent = JSON.stringify(data, null, 2);
};

document.getElementById("urlForm").onsubmit = async (e) => {
  e.preventDefault();
  const url = e.target.url.value;
  const res = await fetch("/analyze-url", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ url }),
  });
  const data = await res.json();
  document.getElementById("output").textContent = JSON.stringify(data, null, 2);
};
