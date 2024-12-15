document.addEventListener("DOMContentLoaded", () => {
    const drawer = document.getElementById("drawer");
    const openDrawerBtn = document.getElementById("openDrawer");
    const closeDrawerBtn = document.getElementById("closeDrawer");

    function openDrawer() {
        drawer.showModal();
        requestAnimationFrame(() => {
            drawer.classList.remove("translate-x-full");
        });
    }

    function closeDrawer() {
        drawer.classList.add("translate-x-full");
        drawer.addEventListener(
            "transitionend",
            () => {
                drawer.close();
            },
            { once: true }
        );
    }

    openDrawerBtn.addEventListener("click", openDrawer);
    closeDrawerBtn.addEventListener("click", closeDrawer);

    const emailInput = document.querySelector("#email");
    const clearIcon = document.querySelector("#clear-icon");
    const continueButton = document.querySelector(".continue-btn");
    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;

    // Function to check if email is valid
    function validateEmail(email) {
        return emailRegex.test(email);
    }

    // Toggle visibility of "X" icon and enable/disable button
    emailInput.addEventListener("input", () => {
        clearIcon.style.visibility = emailInput.value ? "visible" : "hidden";

        if (validateEmail(emailInput.value)) {
            continueButton.disabled = false;
            continueButton.classList.remove("opacity-50");
        } else {
            continueButton.disabled = true;
            continueButton.classList.add("opacity-50");
        }
    });

    // Clear the email field when "X" icon is clicked
    clearIcon.addEventListener("click", () => {
        emailInput.value = "";
        clearIcon.style.visibility = "hidden";
        continueButton.disabled = true;
        continueButton.classList.add("opacity-50");
    });
});
