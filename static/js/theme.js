const toggleButton = document.getElementById("theme-toggle");
const sunIcon = document.getElementById("icon-sun");
const moonIcon = document.getElementById("icon-moon");

document.addEventListener("DOMContentLoaded", () => {
  const savedTheme = localStorage.getItem("theme");
  const root = document.documentElement;

  if (savedTheme === "dark") {
    root.setAttribute("data-theme", "dark");
    moonIcon.style.display = "block";
    sunIcon.style.display = "none";
  } else {
    root.removeAttribute("data-theme");
    sunIcon.style.display = "block";
    moonIcon.style.display = "none";
  }
});

toggleButton.addEventListener("click", () => {
  const root = document.documentElement;
  const currentTheme = root.getAttribute("data-theme");

  if (currentTheme === "dark") {
    root.removeAttribute("data-theme");
    localStorage.setItem("theme", "light");
    sunIcon.style.display = "block";
    moonIcon.style.display = "none";
  } else {
    root.setAttribute("data-theme", "dark");
    localStorage.setItem("theme", "dark");
    moonIcon.style.display = "block";
    sunIcon.style.display = "none";
  }
});
