document.addEventListener("DOMContentLoaded", () => {
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
