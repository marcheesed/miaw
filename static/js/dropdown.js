document.addEventListener("DOMContentLoaded", function () {
  const dropbtn = document.getElementById("dropbtn");
  const dropdownContent = document.getElementById("dropdownContent");

  dropbtn.addEventListener("click", function () {
    dropdownContent.classList.toggle("show");
  });

  document.addEventListener("click", function (event) {
    if (!event.target.closest("#myDropdown")) {
      dropdownContent.classList.remove("show");
    }
  });
});
