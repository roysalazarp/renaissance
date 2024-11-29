const toggleSwitch = document.getElementById("terms");
toggleSwitch.addEventListener("click", function () {
    const isChecked = toggleSwitch.getAttribute("aria-checked") === "true";
    toggleSwitch.setAttribute("aria-checked", String(!isChecked));
    const switchButton = toggleSwitch.querySelector("span");
    if (isChecked) {
        switchButton.classList.remove("translate-x-5");
        switchButton.classList.add("translate-x-0");
        toggleSwitch.classList.remove("bg-blue-600");
        toggleSwitch.classList.add("bg-[#3C3C3C]");
    } else {
        switchButton.classList.remove("translate-x-0");
        switchButton.classList.add("translate-x-5");
        toggleSwitch.classList.remove("bg-[#3C3C3C]");
        toggleSwitch.classList.add("bg-blue-600");
    }
});
