const toggleButton = document.getElementById("theme-toggle");
const sunIcon = document.getElementById("icon-sun");
const moonIcon = document.getElementById("icon-moon");

toggleButton.addEventListener("click", () => {
  const root = document.documentElement;
  const currentTheme = root.getAttribute("data-theme");

  if (currentTheme === "dark") {
    root.removeAttribute("data-theme");
    sunIcon.style.display = "block";
    moonIcon.style.display = "none";
  } else {
    root.setAttribute("data-theme", "dark");
    moonIcon.style.display = "block";
    sunIcon.style.display = "none";
  }
});

document.addEventListener("DOMContentLoaded", () => {
  const root = document.documentElement;
  const currentTheme = root.getAttribute("data-theme");
  if (currentTheme === "dark") {
    moonIcon.style.display = "block";
    sunIcon.style.display = "none";
  } else {
    sunIcon.style.display = "block";
    moonIcon.style.display = "none";
  }
});
